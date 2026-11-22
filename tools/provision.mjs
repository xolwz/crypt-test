import crypto from "node:crypto";

const master = process.env.MASTER_SECRET || process.argv[2] || "";
const buildId = (process.argv[3] || "").toLowerCase();

if (master.length < 32) {
  console.error("usage: MASTER_SECRET=<secret> node tools/provision.mjs <buildId>");
  console.error("   or: node tools/provision.mjs <masterSecret> <buildId>");
  process.exit(1);
}
if (!/^[a-f0-9]{16,64}$/.test(buildId)) {
  console.error("buildId must be 16-64 lowercase hex chars");
  process.exit(1);
}

const key = crypto.createHmac("sha256", master).update(`payload-key:${buildId}`).digest("hex");
const id = crypto.randomBytes(24).toString("hex");

console.log(JSON.stringify({
  buildId,
  payloadKey: key,
  suggestedNonceSeed: id
}, null, 2));
