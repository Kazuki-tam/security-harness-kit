import { Loader2 } from "lucide-react";
import { type ButtonHTMLAttributes, type ReactNode } from "react";

const variantClasses = {
  primary:
    "border-sky-400/35 bg-sky-500/12 text-sky-100 hover:border-sky-400/55 hover:bg-sky-500/20 hover:text-white",
  secondary:
    "border-[var(--color-border)] bg-[var(--color-surface-2)] text-[var(--color-text)] hover:border-sky-400/40 hover:bg-[var(--color-surface-3)] hover:text-white",
} as const;

const sizeClasses = {
  sm: "gap-1.5 rounded-md px-2.5 py-1 text-[11px]",
  md: "gap-2 rounded-lg px-3.5 py-2 text-[13px]",
} as const;

type Props = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: keyof typeof variantClasses;
  size?: keyof typeof sizeClasses;
  icon?: ReactNode;
  loading?: boolean;
};

export function Button({
  variant = "secondary",
  size = "md",
  icon,
  loading = false,
  disabled,
  children,
  className = "",
  ...props
}: Props) {
  const isDisabled = disabled || loading;

  return (
    <button
      type="button"
      disabled={isDisabled}
      className={`inline-flex items-center border font-medium transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400/50 disabled:cursor-not-allowed disabled:opacity-50 ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
      {...props}
    >
      {loading ? (
        <Loader2
          size={size === "sm" ? 12 : 14}
          aria-hidden="true"
          className="shrink-0 animate-spin"
        />
      ) : (
        icon
      )}
      {children}
    </button>
  );
}
