import { SignIn } from '@clerk/nextjs';

export default function SignInPage() {
  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-purple-900 via-violet-900 to-pink-900 p-4">
      <div className="w-full max-w-md">
        <div className="text-center mb-6">
          <h1 className="text-3xl font-bold text-white mb-2">Welcome Back</h1>
          <p className="text-gray-300">Sign in to your Inception account</p>
        </div>
        <SignIn 
          routing="path" 
          path="/sign-in"
          signUpUrl="/sign-up"
          afterSignInUrl="/dashboard"
          appearance={{
            elements: {
              rootBox: "mx-auto",
              card: "bg-black/30 backdrop-blur-xl border border-white/10",
              headerTitle: "text-white",
              headerSubtitle: "text-gray-400",
              socialButtonsBlockButton: "bg-white/10 border-white/20 text-white hover:bg-white/20",
              dividerLine: "bg-white/20",
              dividerText: "text-gray-400",
              formFieldLabel: "text-gray-300",
              formFieldInput: "bg-white/10 border-white/20 text-white placeholder:text-gray-500",
              formButtonPrimary: "bg-purple-600 hover:bg-purple-700",
              footerActionLink: "text-purple-400 hover:text-purple-300",
              formFieldInputShowPasswordButton: "text-gray-400 hover:text-white",
              identityPreviewText: "text-gray-300",
              identityPreviewEditButton: "text-purple-400 hover:text-purple-300",
            }
          }}
        />
      </div>
    </div>
  );
}