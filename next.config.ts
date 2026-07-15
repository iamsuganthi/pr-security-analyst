import type { NextConfig } from "next";
import { withWorkflow } from "workflow/next";

const nextConfig: NextConfig = {
  serverExternalPackages: [
    "@vercel/sandbox",
    "@vercel/oidc",
    "@vercel/cli-config",
    "@vercel/cli-auth",
    "xdg-app-paths",
  ],
};

export default withWorkflow(nextConfig);
