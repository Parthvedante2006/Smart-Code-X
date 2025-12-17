import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from '@/components/ui/accordion';
import {
  AlertTriangle,
  Shield,
  Zap,
  Code2,
  FileCode,
  ChevronRight,
  Download,
  RefreshCw,
} from 'lucide-react';
import type { ReviewResult, Severity, CodeIssue } from '@/types';
import { cn } from '@/lib/utils';

interface ReviewResultsProps {
  result: ReviewResult;
  onNewReview: () => void;
}

const severityConfig: Record<Severity, { color: string; label: string }> = {
  low: { color: 'bg-severity-low', label: 'Low' },
  medium: { color: 'bg-severity-medium', label: 'Medium' },
  high: { color: 'bg-severity-high', label: 'High' },
  critical: { color: 'bg-severity-critical', label: 'Critical' },
};

const categoryConfig: Record<CodeIssue['category'], { icon: typeof Shield; label: string }> = {
  security: { icon: Shield, label: 'Security' },
  performance: { icon: Zap, label: 'Performance' },
  quality: { icon: Code2, label: 'Quality' },
  maintainability: { icon: FileCode, label: 'Maintainability' },
};

function ScoreGauge({ score }: { score: number }) {
  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-success';
    if (score >= 60) return 'text-warning';
    return 'text-destructive';
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="relative w-40 h-40">
      <svg className="w-full h-full transform -rotate-90">
        <circle
          cx="80"
          cy="80"
          r="45"
          stroke="currentColor"
          strokeWidth="10"
          fill="none"
          className="text-muted"
        />
        <circle
          cx="80"
          cy="80"
          r="45"
          stroke="currentColor"
          strokeWidth="10"
          fill="none"
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className={cn('transition-all duration-1000', getScoreColor(score))}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className={cn('text-4xl font-bold', getScoreColor(score))}>{score}</span>
        <span className="text-sm text-muted-foreground">Score</span>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <Badge
      variant="outline"
      className={cn(
        'border-none text-white font-medium',
        severityConfig[severity].color
      )}
    >
      {severityConfig[severity].label}
    </Badge>
  );
}

export function ReviewResults({ result, onNewReview }: ReviewResultsProps) {
  const [expandedFiles, setExpandedFiles] = useState<string[]>([]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold">{result.projectName}</h1>
          <p className="text-muted-foreground">
            Analyzed on {new Date(result.createdAt).toLocaleDateString()}
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm">
            <Download className="mr-2 h-4 w-4" />
            Export Report
          </Button>
          <Button size="sm" onClick={onNewReview} className="bg-gradient-primary hover:opacity-90">
            <RefreshCw className="mr-2 h-4 w-4" />
            New Review
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* Score Card */}
        <Card className="bg-card/50 backdrop-blur-sm border-border/50">
          <CardContent className="pt-6 flex flex-col items-center">
            <ScoreGauge score={result.overallScore} />
            <p className="text-center text-muted-foreground mt-4">
              {result.overallScore >= 80
                ? 'Great job! Your code is in good shape.'
                : result.overallScore >= 60
                  ? 'Some issues need attention.'
                  : 'Critical issues found. Review recommended.'}
            </p>
          </CardContent>
        </Card>

        {/* Issues by Severity */}
        <Card className="bg-card/50 backdrop-blur-sm border-border/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <AlertTriangle className="h-5 w-5" />
              Issues by Severity
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(Object.entries(result.issuesBySeverity) as [Severity, number][])
              .reverse()
              .map(([severity, count]) => (
                <div key={severity} className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={cn('h-3 w-3 rounded-full', severityConfig[severity].color)} />
                    <span className="capitalize">{severity}</span>
                  </div>
                  <span className="font-semibold">{count}</span>
                </div>
              ))}
            <div className="pt-2 border-t border-border">
              <div className="flex items-center justify-between font-medium">
                <span>Total Issues</span>
                <span>{result.totalIssues}</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Issues by Category */}
        <Card className="bg-card/50 backdrop-blur-sm border-border/50">
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Code2 className="h-5 w-5" />
              Issues by Category
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {(Object.entries(result.issuesByCategory) as [CodeIssue['category'], number][]).map(
              ([category, count]) => {
                const config = categoryConfig[category];
                return (
                  <div key={category} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <config.icon className="h-4 w-4 text-muted-foreground" />
                      <span>{config.label}</span>
                    </div>
                    <span className="font-semibold">{count}</span>
                  </div>
                );
              }
            )}
          </CardContent>
        </Card>
      </div>

      {/* Summary */}
      <Card className="bg-card/50 backdrop-blur-sm border-border/50">
        <CardHeader>
          <CardTitle className="text-lg">Summary</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-muted-foreground">{result.summary}</p>
        </CardContent>
      </Card>

      {/* File Analysis */}
      <Card className="bg-card/50 backdrop-blur-sm border-border/50">
        <CardHeader>
          <CardTitle className="text-lg flex items-center gap-2">
            <FileCode className="h-5 w-5" />
            File Analysis ({result.totalFiles} files)
          </CardTitle>
        </CardHeader>
        <CardContent>
          <Accordion type="multiple" value={expandedFiles} onValueChange={setExpandedFiles}>
            {result.files.map((file) => (
              <AccordionItem key={file.path} value={file.path} className="border-border/50">
                <AccordionTrigger className="hover:no-underline">
                  <div className="flex items-center gap-4 w-full pr-4">
                    <div className="flex-1 text-left">
                      <code className="text-sm font-mono">{file.path}</code>
                    </div>
                    <div className="flex items-center gap-4">
                      <div className="flex gap-1">
                        {file.issues.length > 0 ? (
                          (Object.keys(severityConfig) as Severity[])
                            .reverse()
                            .map((sev) => {
                              const count = file.issues.filter((i) => i.severity === sev).length;
                              return count > 0 ? (
                                <Badge
                                  key={sev}
                                  variant="outline"
                                  className={cn(
                                    'border-none text-white text-xs',
                                    severityConfig[sev].color
                                  )}
                                >
                                  {count}
                                </Badge>
                              ) : null;
                            })
                        ) : (
                          <Badge variant="outline" className="bg-success text-success-foreground border-none">
                            Clean
                          </Badge>
                        )}
                      </div>
                      <div className="w-20 text-right">
                        <span className="text-sm text-muted-foreground">{file.score}/100</span>
                      </div>
                    </div>
                  </div>
                </AccordionTrigger>
                <AccordionContent>
                  {file.issues.length > 0 ? (
                    <div className="space-y-3 pt-2">
                      {file.issues.map((issue) => (
                        <div
                          key={issue.id}
                          className="p-4 rounded-lg bg-muted/30 border border-border/50"
                        >
                          <div className="flex items-start justify-between gap-4">
                            <div className="flex-1">
                              <div className="flex items-center gap-2 mb-2">
                                <SeverityBadge severity={issue.severity} />
                                <Badge variant="outline" className="capitalize">
                                  {categoryConfig[issue.category].label}
                                </Badge>
                                <span className="text-xs text-muted-foreground">
                                  Line {issue.line}
                                  {issue.column && `:${issue.column}`}
                                </span>
                              </div>
                              <p className="font-medium">{issue.message}</p>
                              {issue.suggestion && (
                                <p className="text-sm text-muted-foreground mt-1">
                                  💡 {issue.suggestion}
                                </p>
                              )}
                              {issue.code && (
                                <pre className="mt-2 p-2 rounded bg-background/50 text-sm font-mono overflow-x-auto">
                                  <code>{issue.code}</code>
                                </pre>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-muted-foreground py-4 text-center">
                      No issues found in this file. Great job!
                    </p>
                  )}
                </AccordionContent>
              </AccordionItem>
            ))}
          </Accordion>
        </CardContent>
      </Card>
    </div>
  );
}
