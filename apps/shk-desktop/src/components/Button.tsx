import { Loader2 } from "lucide-react";
import { type ButtonHTMLAttributes, type ReactNode } from "react";

const variantClasses = {
  primary:
    "border-sky-500/40 bg-sky-600 text-white shadow-[0_6px_20px_rgba(3,109,240,0.2)] hover:border-sky-400/60 hover:bg-sky-500",
  secondary:
    "border-[var(--color-border)] bg-[var(--color-surface-2)] text-[var(--color-text)] hover:border-sky-300/60 hover:bg-[var(--color-surface-3)] hover:text-white",
} as const;

const sizeClasses = {
  sm: "h-7 gap-1.5 rounded-md px-2.5 text-[11px]",
  md: "h-9 gap-2 rounded-lg px-3.5 text-[13px]",
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
      className={`inline-flex items-center justify-center border font-medium whitespace-nowrap transition focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-300/70 disabled:cursor-not-allowed disabled:opacity-50 ${variantClasses[variant]} ${sizeClasses[size]} ${className}`}
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
