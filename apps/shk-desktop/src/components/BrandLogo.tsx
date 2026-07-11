import appLogo from "../assets/app-logo.png";

type Props = {
  className?: string;
};

export function BrandLogo({ className = "" }: Props) {
  return (
    <img
      src={appLogo}
      alt=""
      aria-hidden="true"
      draggable={false}
      className={`block shrink-0 select-none ${className}`}
    />
  );
}
