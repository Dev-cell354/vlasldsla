"use strict";

const crypto = require("node:crypto");
const { processNetlifyMediaJob, IS_NETLIFY } = require("../../server");

exports.handler = async (event) => {
  const expected = String(process.env.MEDIA_JOB_SECRET || "");
  const supplied = String(event.headers?.["x-omnimun-job-secret"] || event.headers?.["X-Omnimun-Job-Secret"] || "");
  if (!IS_NETLIFY || !expected || supplied.length !== expected.length ||
      !crypto.timingSafeEqual(Buffer.from(supplied), Buffer.from(expected))) {
    return { statusCode: 403, body: "Forbidden" };
  }
  let body;
  try { body = JSON.parse(event.body || "{}"); }
  catch { return { statusCode: 400, body: "Invalid JSON" }; }
  const requestId = String(body.requestId || "");
  if (!/^[a-f0-9-]{36}$/i.test(requestId)) return { statusCode: 400, body: "Invalid requestId" };
  try {
    await processNetlifyMediaJob(requestId);
    return { statusCode: 200, body: "Media job processed" };
  } catch (error) {
    console.error("Netlify media background job failed:", error?.message || error);
    return { statusCode: 500, body: "Media job failed" };
  }
};
