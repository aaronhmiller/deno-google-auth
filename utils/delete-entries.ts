import { load } from "https://deno.land/std@0.224.0/dotenv/mod.ts";

// REMEMBER! When running locally, you CANNOT access the Deno Deploy env vars in Settings

const env = await load();
Deno.env.set("DENO_KV_ACCESS_TOKEN", env["KV_ACCESS_TOKEN"]);

const kv = await Deno.openKv(
  "https://api.deno.com/databases/8d23c11a-7f32-49c9-8538-65efabb15ce6/connect",
);

const prefix = prompt("What prefix:");

// List all entries with the prompted prefix
const entries = kv.list({ prefix: [prefix] });

// Iterate over the entries and delete them
for await (const entry of entries) {
  await kv.delete(entry.key);
  console.log(`Deleted entry with key: ${entry.key}`);
}

console.log("Deletion complete");
