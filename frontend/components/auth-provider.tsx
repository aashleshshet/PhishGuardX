"use client";
import { createContext, useContext } from "react";
import { ClerkProvider, useClerk, useUser } from "@clerk/nextjs";
import type { UserResource } from "@clerk/nextjs/types";
interface Identity {
  configured: boolean;
  loaded: boolean;
  user: UserResource | null;
  openSignIn: () => void;
  openProfile: () => void;
  signOut: () => Promise<void>;
}
const IdentityContext = createContext<Identity>({
  configured: false,
  loaded: true,
  user: null,
  openSignIn: () => {},
  openProfile: () => {},
  signOut: async () => {},
});
export function useIdentity() {
  return useContext(IdentityContext);
}
function IdentityBridge({ children }: { children: React.ReactNode }) {
  const { user, isLoaded } = useUser();
  const clerk = useClerk();
  return (
    <IdentityContext.Provider
      value={{
        configured: true,
        loaded: isLoaded,
        user: user || null,
        openSignIn: () => {
          void clerk.openSignIn();
        },
        openProfile: () => {
          void clerk.openUserProfile();
        },
        signOut: async () => {
          await clerk.signOut();
        },
      }}
    >
      {children}
    </IdentityContext.Provider>
  );
}
export function AuthProvider({ children }: { children: React.ReactNode }) {
  const key = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY;
  if (!key)
    return (
      <IdentityContext.Provider
        value={{
          configured: false,
          loaded: true,
          user: null,
          openSignIn: () => {},
          openProfile: () => {},
          signOut: async () => {},
        }}
      >
        {children}
      </IdentityContext.Provider>
    );
  return (
    <ClerkProvider
      telemetry={false}
      publishableKey={key}
      appearance={{
        variables: {
          colorPrimary: "#3976df",
          fontFamily: "var(--font-google-sans), sans-serif",
          borderRadius: "12px",
        },
      }}
    >
      <IdentityBridge>{children}</IdentityBridge>
    </ClerkProvider>
  );
}
