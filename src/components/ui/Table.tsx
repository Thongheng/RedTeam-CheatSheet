import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronUp, ChevronRight, Search, X } from 'lucide-react';

export interface Column<T> {
    key: string;
    title: string;
    dataIndex: keyof T;
    render?: (value: any, record: T) => React.ReactNode;
    sortable?: boolean;
    filterable?: boolean;
    filters?: { text: string; value: string }[];
    width?: string;
}

interface TableProps<T> {
    columns: Column<T>[];
    data: T[];
    rowKey: (record: T) => string | number;
    expandable?: {
        expandedRowRender: (record: T) => React.ReactNode;
        rowExpandable?: (record: T) => boolean;
    };
    searchable?: boolean;
    searchPlaceholder?: string;
    emptyText?: string;
    className?: string;
}

export function Table<T extends Record<string, any>>({
    columns,
    data,
    rowKey,
    expandable,
    searchable = false,
    searchPlaceholder = 'Search...',
    emptyText = 'No data',
    className = '',
}: TableProps<T>) {
    const [sortConfig, setSortConfig] = useState<{ key: string; direction: 'asc' | 'desc' } | null>(null);
    const [expandedRows, setExpandedRows] = useState<Set<string | number>>(new Set());
    const [searchQuery, setSearchQuery] = useState('');
    const [activeFilters, setActiveFilters] = useState<Record<string, string[]>>({});

    // Filter and sort data
    const processedData = useMemo(() => {
        let result = [...data];

        // Apply search
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            result = result.filter((record) =>
                columns.some((col) => {
                    const value = record[col.dataIndex];
                    return value?.toString().toLowerCase().includes(query);
                })
            );
        }

        // Apply filters
        Object.entries(activeFilters).forEach(([key, values]) => {
            if (values.length > 0) {
                result = result.filter((record) => {
                    const value = record[key];
                    if (Array.isArray(value)) {
                        return values.some((v) => value.includes(v));
                    }
                    return values.includes(value?.toString());
                });
            }
        });

        // Apply sorting
        if (sortConfig) {
            result.sort((a, b) => {
                const aVal = a[sortConfig.key];
                const bVal = b[sortConfig.key];
                if (aVal < bVal) return sortConfig.direction === 'asc' ? -1 : 1;
                if (aVal > bVal) return sortConfig.direction === 'asc' ? 1 : -1;
                return 0;
            });
        }

        return result;
    }, [data, searchQuery, activeFilters, sortConfig, columns]);

    const handleSort = (key: string) => {
        setSortConfig((prev) => {
            if (prev?.key === key) {
                if (prev.direction === 'asc') return { key, direction: 'desc' };
                if (prev.direction === 'desc') return null;
            }
            return { key, direction: 'asc' };
        });
    };

    const toggleFilter = (key: string, value: string) => {
        setActiveFilters((prev) => {
            const current = prev[key] || [];
            const next = current.includes(value)
                ? current.filter((v) => v !== value)
                : [...current, value];
            return { ...prev, [key]: next };
        });
    };

    const toggleRow = (id: string | number) => {
        setExpandedRows((prev) => {
            const next = new Set(prev);
            if (next.has(id)) next.delete(id);
            else next.add(id);
            return next;
        });
    };

    return (
        <div className={`w-full ${className}`}>
            {/* Search Bar */}
            {searchable && (
                <div className="mb-4 relative">
                    <input
                        type="text"
                        value={searchQuery}
                        onChange={(e) => setSearchQuery(e.target.value)}
                        placeholder={searchPlaceholder}
                        className="w-full bg-[#0d1117] border border-white/10 rounded-lg px-4 py-2.5 pl-10 text-sm text-white placeholder:text-gray-600 focus:border-[#a2ff00]/50 focus:outline-none"
                    />
                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
                    {searchQuery && (
                        <button
                            onClick={() => setSearchQuery('')}
                            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-white"
                        >
                            <X size={16} />
                        </button>
                    )}
                </div>
            )}

            {/* Table */}
            <div className="overflow-x-auto rounded-xl border border-white/5">
                <table className="w-full border-collapse">
                    <thead>
                        <tr className="bg-[#0d1117]">
                            {expandable && <th className="w-10 p-3"></th>}
                            {columns.map((col) => (
                                <th
                                    key={col.key}
                                    className={`p-4 text-left text-xs font-bold text-gray-400 uppercase tracking-wider border-b border-white/5 ${col.sortable ? 'cursor-pointer hover:text-[#a2ff00] transition-colors' : ''
                                        }`}
                                    style={{ width: col.width }}
                                    onClick={() => col.sortable && handleSort(col.key)}
                                >
                                    <div className="flex items-center gap-2">
                                        {col.title}
                                        {col.sortable && (
                                            <span className="flex flex-col">
                                                <ChevronUp
                                                    size={12}
                                                    className={sortConfig?.key === col.key && sortConfig.direction === 'asc' ? 'text-[#a2ff00]' : 'text-gray-600'}
                                                />
                                                <ChevronDown
                                                    size={12}
                                                    className={sortConfig?.key === col.key && sortConfig.direction === 'desc' ? 'text-[#a2ff00]' : 'text-gray-600'}
                                                    style={{ marginTop: '-4px' }}
                                                />
                                            </span>
                                        )}
                                    </div>
                                    {/* Filter dropdown */}
                                    {col.filters && col.filters.length > 0 && (
                                        <div className="mt-2 flex flex-wrap gap-1">
                                            {col.filters.map((filter) => (
                                                <button
                                                    key={filter.value}
                                                    onClick={(e) => {
                                                        e.stopPropagation();
                                                        toggleFilter(col.dataIndex as string, filter.value);
                                                    }}
                                                    className={`px-2 py-0.5 text-[10px] rounded border transition-colors ${activeFilters[col.dataIndex as string]?.includes(filter.value)
                                                        ? 'bg-[#a2ff00]/20 text-[#a2ff00] border-[#a2ff00]/30'
                                                        : 'bg-white/5 text-gray-500 border-white/10 hover:text-white'
                                                        }`}
                                                >
                                                    {filter.text}
                                                </button>
                                            ))}
                                        </div>
                                    )}
                                </th>
                            ))}
                        </tr>
                    </thead>
                    <tbody>
                        {processedData.length === 0 ? (
                            <tr>
                                <td colSpan={columns.length + (expandable ? 1 : 0)} className="p-8 text-center text-gray-500">
                                    {emptyText}
                                </td>
                            </tr>
                        ) : (
                            processedData.map((record) => {
                                const id = rowKey(record);
                                const isExpanded = expandedRows.has(id);
                                const canExpand = expandable && (!expandable.rowExpandable || expandable.rowExpandable(record));

                                return (
                                    <React.Fragment key={id}>
                                        <tr className="border-b border-white/5 hover:bg-white/[0.02] transition-colors">
                                            {expandable && (
                                                <td className="p-3">
                                                    {canExpand && (
                                                        <button
                                                            onClick={() => toggleRow(id)}
                                                            className="text-gray-500 hover:text-[#a2ff00] transition-colors"
                                                        >
                                                            <ChevronRight
                                                                size={16}
                                                                className={`transform transition-transform ${isExpanded ? 'rotate-90' : ''}`}
                                                            />
                                                        </button>
                                                    )}
                                                </td>
                                            )}
                                            {columns.map((col) => (
                                                <td key={col.key} className="p-4 text-sm text-gray-300">
                                                    {col.render ? col.render(record[col.dataIndex], record) : record[col.dataIndex]}
                                                </td>
                                            ))}
                                        </tr>
                                        {/* Expanded Row */}
                                        {isExpanded && expandable && (
                                            <tr className="bg-[#0a0d11]">
                                                <td colSpan={columns.length + 1} className="p-4">
                                                    {expandable.expandedRowRender(record)}
                                                </td>
                                            </tr>
                                        )}
                                    </React.Fragment>
                                );
                            })
                        )}
                    </tbody>
                </table>
            </div>

            {/* Footer */}
            <div className="mt-3 text-xs text-gray-500 flex items-center justify-between">
                <span>Showing {processedData.length} of {data.length} items</span>
                {Object.values(activeFilters).some((f) => f.length > 0) && (
                    <button
                        onClick={() => setActiveFilters({})}
                        className="text-[#a2ff00] hover:underline"
                    >
                        Clear filters
                    </button>
                )}
            </div>
        </div>
    );
}

export default Table;
