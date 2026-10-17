import { redirect } from "next/navigation";

// Render on each request so the server emits a real 307 with a Location header
// rather than a statically-prerendered redirect (which has no Location).
export const dynamic = "force-dynamic";

export default function Home() {
  redirect("/dashboard");
}
