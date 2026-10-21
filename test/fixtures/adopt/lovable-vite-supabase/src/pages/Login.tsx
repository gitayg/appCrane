import { useState } from "react";
import { supabase } from "@/integrations/supabase/client";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const submit = async () => {
    await supabase.auth.signInWithPassword({ email, password });
  };
  return <button onClick={submit}>Sign in</button>;
}
