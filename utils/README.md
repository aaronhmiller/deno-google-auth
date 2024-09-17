# Delete Tool

## NOTE

It took a lot of struggle trying to read from Deno Deploy Settings, before
realizing that those settings are ONLY when you're running in the Deno Deploy
Environment. I was running LOCALLY, which demands a different approach. Namely,
using a .env file (not checked into the repo for security reasons) but to use
this tool, you should create one and populate it with a line like this:
`KV_ACCESS_TOKEN=<YOUR_ACCCESS_TOKEN_HERE>`

With that, the tool will run after prompting you for the prefix(es) to delete.

## Usage

`deno run --unstable-kv -A delete-entries.ts`
