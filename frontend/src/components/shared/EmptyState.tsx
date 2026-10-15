interface Props {
  title: string
  description?: string
  icon?: React.ReactNode
}

export function EmptyState({ title, description, icon }: Props) {
  return (
    <div className="flex flex-col items-center justify-center py-16 px-6 text-center">
      {icon ? (
        <div className="mb-4 text-slate-600">{icon}</div>
      ) : (
        <div className="mb-4 w-12 h-12 rounded-full bg-navy-700 flex items-center justify-center" aria-hidden="true">
          <svg className="w-6 h-6 text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
      )}
      <p className="text-slate-300 font-medium">{title}</p>
      {description && (
        <p className="mt-1 text-slate-500 text-sm">{description}</p>
      )}
    </div>
  )
}
