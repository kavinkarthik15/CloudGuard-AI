interface Props {
  size?: 'sm' | 'md' | 'lg'
  label?: string
}

export function LoadingSpinner({ size = 'md', label = 'Loading…' }: Props) {
  const sizeClasses = {
    sm: 'w-4 h-4 border-2',
    md: 'w-8 h-8 border-2',
    lg: 'w-12 h-12 border-3',
  }[size]

  return (
    <div role="status" className="flex items-center justify-center gap-3">
      <div
        className={`${sizeClasses} rounded-full border-navy-600 border-t-aws-500 animate-spin`}
        aria-hidden="true"
      />
      <span className="sr-only">{label}</span>
      {size !== 'sm' && (
        <span className="text-slate-400 text-sm">{label}</span>
      )}
    </div>
  )
}
