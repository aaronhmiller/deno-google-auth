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
      // Check if they've already signed in
      const sessionId = await getSessionId(request);
      if (sessionId) {
        // Redirect to the home page
        const url = new URL(request.url);
        const redirectUrl = `${url.origin}/`;
        return Response.redirect(redirectUrl, 302);
      } else {
        // Generate a unique state parameter
        const state = crypto.randomUUID();
    
        // Store the state in Deno KV using a unique key
        const stateKey = crypto.randomUUID();
        await kv.set(["oauth_state", stateKey], state);
    
        // Set a cookie with the stateKey
        const response = await signIn(request, { state });
        response.headers.append(
          "Set-Cookie",
          `stateKey=${stateKey}; Path=/; HttpOnly; Secure; SameSite=Lax`,
        );
    
        return response;
      }
    }



    case "/callback": {
      try {
        // Retrieve the state parameter from the callback URL
        const url = new URL(request.url);
        const returnedState = url.searchParams.get("state");
        if (!returnedState) {
          return new Response("State parameter is missing.", { status: 400 });
        }
    
        // Get the stateKey from cookies
        const cookieHeader = request.headers.get("Cookie") || "";
        const cookies = new Map(
          cookieHeader.split(";").map((c) => c.trim().split("=") as [string, string]),
        );
        const stateKey = cookies.get("stateKey");
        if (!stateKey) {
          return new Response("State key is missing in cookies.", { status: 400 });
        }
    
        // Retrieve the stored state
        const storedStateEntry = await kv.get(["oauth_state", stateKey]);
        if (!storedStateEntry.value) {
          return new Response("Stored state not found.", { status: 400 });
        }
        const storedState = storedStateEntry.value as string;
    
        // Validate the state
        if (returnedState !== storedState) {
          return new Response("Invalid state parameter.", { status: 400 });
        }
    
        // State is valid; proceed with token exchange
        const { tokens } = await handleCallback(request);
    
        // Now check if the user is already signed in
        const sessionId = await getSessionId(request);
        if (sessionId) {
          // Redirect to home page
          return Response.redirect(`${url.origin}/`, 302);
        }


        // Clean up the stored state and stateKey cookie
        await kv.delete(["oauth_state", stateKey]);
    
        const response = Response.redirect(`${url.origin}/fetch-user-info`, 302);
        response.headers.append(
          "Set-Cookie",
          `stateKey=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`,
        );
    
        return response;
      } catch (error) {
        console.error("Error in callback:", error);
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
