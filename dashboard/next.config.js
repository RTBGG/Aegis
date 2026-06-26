/** @type {import('next').NextConfig} */
// In production the edge serves /api/* straight to the control plane (same
// origin), so these rewrites only matter when running `next dev` directly.
const apiProxy = process.env.API_PROXY || "http://localhost:8080";

module.exports = {
  output: "standalone",
  async rewrites() {
    return [
      { source: "/api/:path*", destination: `${apiProxy}/api/:path*` },
    ];
  },
};
