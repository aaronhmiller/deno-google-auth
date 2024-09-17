import { Application, serve } from "jsr:@oak/oak@16.1.0";
import {
  createGoogleOAuthConfig,
  createHelpers,
} from "jsr:@deno/kv-oauth@0.11.0";
import { STATUS_CODE } from "jsr:@std/http@0.224.5/status";

const oauthConfig = createGoogleOAuthConfig({
  redirectUri: `${Deno.env.get("BASE_URL")}/callback`,
  scope:
    "https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email",
});

const { getSessionId, signIn, signOut, handleCallback } = createHelpers(
  oauthConfig,
);

const ALLOWED_EMAILS = Deno.env.get("ALLOWED_EMAILS");

// Use Deno KV to store user emails
const kv = await Deno.openKv();


function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};
  const pairs = cookieHeader.split(/; */);
  for (const pair of pairs) {
    const eqIndex = pair.indexOf('=');
    if (eqIndex < 0) continue;
    const key = decodeURIComponent(pair.slice(0, eqIndex).trim());
    const val = decodeURIComponent(pair.slice(eqIndex + 1).trim());
    cookies[key] = val;
  }
  return cookies;
}

async function indexHandler(request: Request) {

  const sessionId = await getSessionId(request);
  const hasSessionIdCookie = sessionId !== undefined;
  let userEmail = "";

  if (hasSessionIdCookie) {
    const emailEntry = await kv.get(["user_email", sessionId]);
    userEmail = (emailEntry.value as string) || "";
  }


  const body = `
    <p>Authorization endpoint URI: ${oauthConfig.authorizationEndpointUri}</p>
    <p>Token URI: ${oauthConfig.tokenUri}</p>
    <p>Scope: ${oauthConfig.defaults?.scope}</p>
    <p>Signed in: ${hasSessionIdCookie}</p>
    ${userEmail ? `<p>Signed in as: ${userEmail}</p>` : ""}
    <p>
      <a href="/signin">Sign in</a>
    </p>
    <p>
      <a href="/signout">Sign out</a>
    </p>
  `;
  return new Response(body, {
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

async function handler(request: Request): Promise<Response> {
  if (request.method !== "GET") {
    return new Response(null, { status: STATUS_CODE.NotFound });
  }
  switch (new URL(request.url).pathname) {
    case "/": {
      return await indexHandler(request);
    }

    case "/signin": {
      const sessionId = await getSessionId(request);
      if (sessionId) {
        const url = new URL(request.url);
        const redirectUrl = `${url.origin}/`;
        return Response.redirect(redirectUrl, 302);
      } else {
        const state = crypto.randomUUID();
        const stateKey = crypto.randomUUID();
        await kv.set(["oauth_state", stateKey], state);
        console.log("Generated state:", state);
        console.log("Generated stateKey:", stateKey);
    
        const signInResponse = await signIn(request, { state });
        signInResponse.headers.append(
          "Set-Cookie",
          `stateKey=${encodeURIComponent(stateKey)}; Path=/; HttpOnly; SameSite=Lax`,
        );
    
        return signInResponse;
      }
    }

    case "/callback": {
      try {
        const url = new URL(request.url);
        const returnedState = url.searchParams.get("state");
        if (!returnedState) {
          console.error("State parameter is missing.");
          return new Response("State parameter is missing.", { status: 400 });
        }
    
        const cookieHeader = request.headers.get("Cookie") || "";
        const cookies = parseCookies(cookieHeader);
        const stateKey = cookies["stateKey"];
        if (!stateKey) {
          console.error("State key is missing in cookies.");
          return new Response("State key is missing in cookies.", { status: 400 });
        }
    
        const storedStateEntry = await kv.get(["oauth_state", stateKey]);
        if (!storedStateEntry.value) {
          console.error(`Stored state not found for stateKey: ${stateKey}`);
          return new Response("Stored state not found.", { status: 400 });
        }
        const storedState = storedStateEntry.value as string;
    
        console.log("Returned state:", returnedState);
        console.log("Stored state:", storedState);
    
        if (returnedState !== storedState) {
          console.error(
            "Invalid state parameter. Returned:",
            returnedState,
            "Expected:",
            storedState,
          );
          return new Response("Invalid state parameter.", { status: 400 });
        }
    
        // Proceed with token exchange
        const { tokens } = await handleCallback(request);
    
        // Clean up
        await kv.delete(["oauth_state", stateKey]);
    
        const response = new Response(null, {
          status: 302,
          headers: {
            "Location": `${url.origin}/fetch-user-info`,
            "Set-Cookie": `stateKey=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax`,
          },
        });
    
        return response;
      } catch (error) {
        console.error("Error in callback:", error.message, error.stack);
        return new Response("An error occurred during authentication.", {
          status: 500,
        });
      }
    }

/*
    case "/callback": {
      try {
        const sessionId = await getSessionId(request);
        if (sessionId) {
          // User is already signed in, redirect them
          const url = new URL(request.url);
          const redirectUrl = `${url.origin}/`;
          return Response.redirect(redirectUrl, 302);
        }
    
        const { response, tokens, sessionId: newSessionId } = await handleCallback(request);

        // Fetch user info
        const userInfoResponse = await fetch(
          "https://www.googleapis.com/oauth2/v2/userinfo",
          {
            headers: {
              Authorization: `Bearer ${tokens.accessToken}`,
            },
          },
        );
        const userInfo = await userInfoResponse.json();

        // Check if the email is allowed
        if (!ALLOWED_EMAILS.includes(userInfo.email)) {
          await signOut(request);
          await kv.delete(["site_sessions", sessionId]);
          const redirectUrl = new URL(`${Deno.env.get("BASE_URL")}/signout`);
          // Redirect to the signout page
          return Response.redirect(redirectUrl, 302);

        }

        // Store the email in Deno KV
        await kv.set(["user_email", sessionId], userInfo.email);

        return response;
      } catch (error) {
        console.error("Error in callback:", error);
        return new Response(null, { status: STATUS_CODE.InternalServerError });
      }
    }
*/

    case "/fetch-user-info": {
      try {
        const sessionId = await getSessionId(request);
        if (!sessionId) {
          // User is not signed in, redirect to sign-in page
          const url = new URL(request.url);
          const redirectUrl = `${url.origin}/signin`;
          return Response.redirect(redirectUrl, 302);
        }
    
        // Retrieve the tokens from the session (if stored)
        const tokens = await kv.get(["oauth_tokens", sessionId]);
        if (!tokens.value) {
          // Tokens not found, redirect to sign-in
          const url = new URL(request.url);
          const redirectUrl = `${url.origin}/signin`;
          return Response.redirect(redirectUrl, 302);
        }
    
        // Fetch user info
        const userInfoResponse = await fetch(
          "https://www.googleapis.com/oauth2/v2/userinfo",
          {
            headers: {
              Authorization: `Bearer ${tokens.value.accessToken}`,
            },
          },
        );
        const userInfo = await userInfoResponse.json();
    
        // Check if the email is allowed
        if (!ALLOWED_EMAILS.includes(userInfo.email)) {
          await signOut(request);
          return new Response("Access denied. Your email is not authorized.", {
            status: 403,
          });
        }
    
        // Store the email in Deno KV
        await kv.set(["user_email", sessionId], userInfo.email);
    
        // Redirect to the home page
        const url = new URL(request.url);
        const redirectUrl = `${url.origin}/`;
        return Response.redirect(redirectUrl, 302);
      } catch (error) {
        console.error("Error in fetch-user-info:", error);
        return new Response("An error occurred while fetching user info.", { status: 500 });
      }
    }
    




    case "/signout": {
      const sessionId = await getSessionId(request);
      if (sessionId) {
        await kv.delete(["user_email", sessionId]);
      }

      const response = await signOut(request);
      response.headers.append(
        "Set-Cookie",
        "__Host-oauth-session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax",
      );
      response.headers.append(
        "Set-Cookie",
        "__Host-site-session=; Path=/; Max-Age=0;	Secure; HttpOnly; SameSite=Lax",
      );

      return response;
    }
    default: {
      return new Response(null, { status: STATUS_CODE.NotFound });
    }
  }
}

const app = new Application();
app.use(serve(handler));
const port = 8000;
app.listen({ port });
console.log(`Listening on http://localhost:${port}/`);
