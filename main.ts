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
        const url = new URL(request.url);
        const redirectUrl = `${url.origin}/`;
        // Redirect to the index page
        return Response.redirect(redirectUrl, 302);
      } else {  
        return await signIn(request);
      }
    }



    case "/callback": {
      try {
        const sessionId = await getSessionId(request);
        if (sessionId) {
          // User is already signed in, redirect them
          const url = new URL(request.url);
          const redirectUrl = `${url.origin}/`;
          return Response.redirect(redirectUrl, 302);
        }
    
        // Proceed with the normal OAuth callback handling
        const { tokens } = await handleCallback(request);
    
        // Redirect to fetch user info
        const url = new URL(request.url);
        const redirectUrl = `${url.origin}/fetch-user-info`;
    
        // Create a new Response object for the redirect
        return new Response(null, {
          status: 302,
          headers: {
            "Location": redirectUrl,
          },
        });
      } catch (error) {
        console.error("Error in callback:", error);
        return new Response("An error occurred during authentication.", { status: 500 });
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
