interface Props {
  isOffline: boolean;
}

export function OfflineIndicator({ isOffline }: Props) {
  if (!isOffline) {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-green-600">
        <span className="h-2 w-2 rounded-full bg-green-500" aria-hidden="true" />
        Online
      </span>
    );
  }

  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-amber-600">
      <span className="h-2 w-2 rounded-full bg-amber-500" aria-hidden="true" />
      Offline
    </span>
  );
}
