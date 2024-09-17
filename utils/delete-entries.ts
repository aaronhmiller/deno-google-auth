import { load } from "https://deno.land/std@0.224.0/dotenv/mod.ts";

// REMEMBER! When running locally, you CANNOT access the Deno Deploy env vars in Settings

const env = await load();
Deno.env.set("DENO_KV_ACCESS_TOKEN", env["KV_ACCESS_TOKEN"]);
const KV_UUID = env["KV_UUID"];

let kv: Deno.Kv; //just for scope

try {
  kv = await Deno.openKv(
    "https://api.deno.com/databases/" + `${KV_UUID}` + "/connect",
  );
} catch (error) {
  console.log("Cannot connect to KV. Exiting.");
  Deno.exit(1);
}
const prefix = prompt("What prefix:");

// List all entries with the prompted prefix
const entries = await kv.list({ prefix: [prefix] });

// Iterate over the entries and delete them
for await (const entry of entries) {
  await kv.delete(entry.key);
  console.log(`Deleted entry with key: ${entry.key}`);
}

console.log("Deletion complete");
