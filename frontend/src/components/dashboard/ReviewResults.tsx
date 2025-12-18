import { useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
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
  Download,
  RefreshCw,
  Lightbulb,
  Search,
  BrainCircuit,
  CheckCircle2
} from 'lucide-react';
import type { ReviewResult, Severity, CodeIssue, IERARecommendation } from '@/types';
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
        <circle cx="80" cy="80" r="45" stroke="currentColor" strokeWidth="10" fill="none" className="text-muted" />
        <circle
          cx="80" cy="80" r="45" stroke="currentColor" strokeWidth="10" fill="none"
          strokeDasharray={circumference} strokeDashoffset={strokeDashoffset} strokeLinecap="round"
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

function RecommendationCard({ rec }: { rec: IERARecommendation }) {
  return (
    <Card className="border-l-4 border-l-primary/50 hover:shadow-md transition-shadow">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between">
          <div>
            <CardTitle className="text-lg text-primary">{rec.title}</CardTitle>
            <CardDescription className="capitalize mt-2 flex items-center gap-2 flex-wrap">
              <Badge variant="outline">{rec.category.replace('_', ' ')}</Badge>
              <Badge variant={rec.strength === 'Strong Suggestion' ? 'default' : 'secondary'}>
                {rec.strength || 'Info'}
              </Badge>
              <Badge variant="secondary" className="bg-muted">Effort: {rec.effort}</Badge>
              <Badge variant="secondary" className="bg-muted">Impact: {rec.impact}</Badge>
            </CardDescription>
          </div>
          <div className="text-sm font-bold text-primary whitespace-nowrap ml-4">
            {Math.round((rec.evidence?.similarity_score || 0.95) * 100)}% Conf
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {rec.explanation && (
          <div className="bg-primary/5 p-3 rounded-md border border-primary/10">
            <p className="font-semibold text-primary mb-1 flex items-center gap-2">
              <Lightbulb className="h-4 w-4" /> Why this matters
            </p>
            <p className="text-foreground/90 leading-relaxed">{rec.explanation}</p>
          </div>
        )}

        <div className="text-muted-foreground">
          {rec.description}
        </div>

        {rec.suggestions && rec.suggestions.length > 0 && (
          <div className="space-y-2">
            <h4 className="font-semibold flex items-center gap-2 text-foreground">
              <CheckCircle2 className="h-4 w-4 text-green-500" />
              Suggested Actions
            </h4>
            <ul className="list-disc list-inside space-y-1 ml-1">
              {rec.suggestions.map((suggestion, idx) => (
                <li key={idx} className="text-muted-foreground pl-2">{suggestion}</li>
              ))}
            </ul>
          </div>
        )}

        {rec.implementation_example && (
          <div className="bg-muted p-3 rounded-md overflow-x-auto mt-2">
            <p className="text-xs font-semibold text-muted-foreground mb-2">Example:</p>
            <pre className="text-xs font-mono">{rec.implementation_example}</pre>
          </div>
        )}

        <div className="pt-2 border-t mt-4">
          <div className="flex items-start gap-2 text-xs text-muted-foreground">
            <FileCode className="h-4 w-4 mt-0.5" />
            <div className="flex flex-col gap-1">
              <span className="font-semibold">Affected Files:</span>
              <div className="flex flex-wrap gap-1">
                {rec.files && rec.files.map((f, i) => (
                  <code key={i} className="bg-muted px-1.5 py-0.5 rounded text-foreground/80">{f}</code>
                ))}
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function ReviewResults({ result, onNewReview }: ReviewResultsProps) {
  const [expandedFiles, setExpandedFiles] = useState<string[]>([]);
  const rawData = result.raw_analysis?.agents;

  // IERA Recommendations
  const recommendations = rawData?.IERA?.recommendations || [];

  // HDVA
  const hallucinations = rawData?.HDVA?.issues || [];
  const hdvaSummary = rawData?.HDVA?.summary || {};

  // SCAA
  const scaaSummary = rawData?.SCAA?.summary || {};

  const handleDownloadReport = () => {
    const lines = [
      `# SmartCodeX Analysis Report`,
      `Project: ${result.projectName}`,
      `Date: ${new Date(result.createdAt).toLocaleString()}`,
      `Overall Score: ${result.overallScore}/100`,
      `\n## Summary`,
      result.summary,
      `\n## Statistics`,
      `- Total Issues: ${result.totalIssues}`,
      `- Files Analyzed: ${result.files.length}`,
      `- AI Insights: ${recommendations.length}`,
      `- Hallucinations: ${hallucinations.length}`,
      `\n## Issues by Severity`,
      `- Critical: ${result.issuesBySeverity.critical}`,
      `- High: ${result.issuesBySeverity.high}`,
      `- Medium: ${result.issuesBySeverity.medium}`,
      `- Low: ${result.issuesBySeverity.low}`,
      `\n## Detailed Issues`,
    ];

    const severityIcons: Record<string, string> = {
      critical: '🔴',
      high: '🟠',
      medium: '🟡',
      low: '🔵'
    };

    result.files.forEach(file => {
      if (file.issues.length > 0) {
        lines.push(`\n### File: ${file.path}`);
        file.issues.forEach(issue => {
          const icon = severityIcons[issue.severity] || '⚪';
          lines.push(`- ${icon} [${issue.severity.toUpperCase()}] Line ${issue.line}: ${issue.message}`);
        });
      }
    });

    if (recommendations.length > 0) {
      lines.push(`\n## AI Recommendations (IERA)`);
      recommendations.forEach(rec => {
        lines.push(`\n### ${rec.title}`);
        lines.push(`- **Category**: ${rec.category.replace('_', ' ')}`);
        lines.push(`- **Confidence**: ${Math.round((rec.evidence?.similarity_score || rec.confidence || 0.95) * 100)}%`);
        lines.push(`- **Impact**: ${rec.impact} | **Effort**: ${rec.effort}`);

        if (rec.explanation) {
          lines.push(`\n**Why this matters:**`);
          lines.push(rec.explanation);
        } else {
          lines.push(`\n${rec.description}`);
        }

        if (rec.suggestions && rec.suggestions.length > 0) {
          lines.push(`\n**Suggested Actions:**`);
          rec.suggestions.forEach(s => lines.push(`- ${s}`));
        }

        if (rec.files && rec.files.length > 0) {
          lines.push(`\n**Affected Files:**`);
          rec.files.forEach(f => lines.push(`- \`${f}\``));
        }

        if (rec.implementation_example) {
          lines.push('\n**Example:**');
          lines.push('```');
          lines.push(rec.implementation_example);
          lines.push('```');
        }
        lines.push('\n---');
      });
    }

    const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `smartcodex-report-${result.projectName.replace(/\s+/g, '-').toLowerCase()}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

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
          <Button size="sm" onClick={handleDownloadReport} variant="outline" className="border-primary text-primary hover:bg-primary hover:text-white transition-all">
            <Download className="mr-2 h-4 w-4" />
            Download Report
          </Button>
          <Button size="sm" onClick={onNewReview} className="bg-gradient-primary hover:opacity-90">
            <RefreshCw className="mr-2 h-4 w-4" />
            New Review
          </Button>
        </div>
      </div>

      <Tabs defaultValue="overview" className="w-full">
        <TabsList className="grid w-full grid-cols-4 lg:w-[600px]">
          <TabsTrigger value="overview">Overview</TabsTrigger>
          <TabsTrigger value="issues">Issues</TabsTrigger>
          <TabsTrigger value="recommendations">AI Insights</TabsTrigger>
          <TabsTrigger value="deep_analysis">Deep Analysis</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-6 mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            <Card className="bg-card/50 backdrop-blur-sm">
              <CardContent className="pt-6 flex flex-col items-center">
                <ScoreGauge score={result.overallScore} />
              </CardContent>
            </Card>

            <Card className="bg-card/50 backdrop-blur-sm lg:col-span-2">
              <CardHeader>
                <CardTitle>Analysis Summary</CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-lg leading-relaxed">
                  {result.summary}
                </p>
                <div className="grid grid-cols-4 gap-4 mt-6">
                  {Object.entries(result.issuesBySeverity).map(([severity, count]) => {
                    const colorMap: Record<string, string> = {
                      low: 'text-emerald-500 border-emerald-500/20 bg-emerald-500/10',
                      medium: 'text-amber-500 border-amber-500/20 bg-amber-500/10',
                      high: 'text-orange-500 border-orange-500/20 bg-orange-500/10',
                      critical: 'text-red-500 border-red-500/20 bg-red-500/10'
                    };
                    const colorClass = colorMap[severity.toLowerCase()] || 'text-primary';

                    return (
                      <div key={severity} className={cn("p-4 rounded-lg border flex flex-col items-center justify-center transition-colors", colorClass)}>
                        <div className="text-2xl font-bold capitalize">
                          {count}
                        </div>
                        <div className="text-xs uppercase tracking-wider mt-1 font-semibold">{severity}</div>
                      </div>
                    );
                  })}
                </div>

                <div className="grid grid-cols-3 gap-4 mt-6">
                  <div className="p-4 rounded-lg bg-background/50 border">
                    <div className="text-2xl font-bold">{result.totalIssues}</div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wider">Total Issues</div>
                  </div>
                  <div className="p-4 rounded-lg bg-background/50 border">
                    <div className="text-2xl font-bold">{recommendations.length}</div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wider">AI Suggestions</div>
                  </div>
                  <div className="p-4 rounded-lg bg-background/50 border">
                    <div className="text-2xl font-bold">{hallucinations.length}</div>
                    <div className="text-xs text-muted-foreground uppercase tracking-wider">Hallucinations</div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="issues" className="mt-6">
          <Card className="bg-card/50 backdrop-blur-sm border-border/50">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <FileCode className="h-5 w-5" />
                Static Analysis Issues ({result.totalFiles} files)
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
                        <div className="flex items-center gap-2">
                          {file.issues.length > 0 ? (
                            <Badge variant="outline" className="text-warning border-warning/50">
                              {file.issues.length} Issues
                            </Badge>
                          ) : (
                            <Badge variant="outline" className="text-success border-success/50">Clean</Badge>
                          )}
                        </div>
                      </div>
                    </AccordionTrigger>
                    <AccordionContent>
                      {file.issues.length > 0 ? (
                        <div className="space-y-3 pt-2">
                          {file.issues.map((issue) => (
                            <div key={issue.id} className="p-4 rounded-lg bg-muted/30 border border-border/50">
                              <div className="flex items-start justify-between gap-4">
                                <div>
                                  <div className="flex items-center gap-2 mb-2">
                                    <Badge className={cn('capitalize text-white', severityConfig[issue.severity].color)}>
                                      {issue.severity}
                                    </Badge>
                                    <span className="text-xs text-muted-foreground">Line {issue.line}</span>
                                  </div>
                                  <p className="text-sm font-medium">{issue.message}</p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      ) : <p className="text-muted-foreground p-4 text-center text-sm">No issues found.</p>}
                    </AccordionContent>
                  </AccordionItem>
                ))}
              </Accordion>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="recommendations" className="mt-6 space-y-6">
          <h2 className="text-xl font-bold flex items-center gap-2">
            <Lightbulb className="h-5 w-5 text-yellow-500" />
            Intelligent Recommendations (IERA)
          </h2>
          {recommendations.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {recommendations.map((rec: IERARecommendation, idx: number) => (
                <RecommendationCard key={idx} rec={rec} />
              ))}
            </div>
          ) : (
            <Card><CardContent className="p-8 text-center text-muted-foreground">No recommendations generated for this codebase.</CardContent></Card>
          )}
        </TabsContent>

        <TabsContent value="deep_analysis" className="mt-6 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* Hallucination Card */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <BrainCircuit className="h-5 w-5 text-purple-500" />
                  Hallucination Detection
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="p-4 bg-muted/30 rounded-lg mb-4 text-center">
                  <div className="text-3xl font-bold">{hallucinations.length}</div>
                  <div className="text-xs text-muted-foreground">Potential Hallucinations Found</div>
                </div>
                {hallucinations.length > 0 ? (
                  <ul className="space-y-2">
                    {hallucinations.map((h: any, i: number) => (
                      <li key={i} className="text-sm p-2 border rounded bg-background">
                        <span className="font-bold">{h.file}</span>: {h.issue} (Prob: {h.probability})
                      </li>
                    ))}
                  </ul>
                ) : <div className="flex items-center gap-2 text-success text-sm justify-center"><CheckCircle2 className="h-4 w-4" /> No hallucinations detected.</div>}
              </CardContent>
            </Card>

            {/* Semantic Analysis Card */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5 text-blue-500" />
                  Semantic Analysis
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="flex justify-between items-center p-3 border rounded bg-muted/20">
                    <span className="text-sm">Issues Found</span>
                    <span className="font-bold">{scaaSummary.issues_found ?? 0}</span>
                  </div>
                  <div className="flex justify-between items-center p-3 border rounded bg-muted/20">
                    <span className="text-sm">Files Analyzed</span>
                    <span className="font-bold">{scaaSummary.files_analyzed ?? 0}</span>
                  </div>
                  <div className="flex justify-between items-center p-3 border rounded bg-muted/20">
                    <span className="text-sm">Avg Similarity</span>
                    <span className="font-bold">{(scaaSummary.average_similarity ?? 0).toFixed(2)}</span>
                  </div>
                </div>

                {rawData?.SCAA?.issues?.length > 0 ? (
                  <div className="mt-4 space-y-3">
                    <h3 className="text-sm font-semibold text-muted-foreground">Detected Issues</h3>
                    {rawData.SCAA.issues.map((issue: any, idx: number) => (
                      <div key={idx} className="p-3 border rounded-lg bg-background/50 text-sm space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="font-mono font-bold text-primary">{issue.function}()</div>
                          <Badge variant="outline" className={cn(
                            issue.severity === 'High' ? 'text-orange-500 border-orange-500/20' :
                              issue.severity === 'Medium' ? 'text-amber-500 border-amber-500/20' :
                                'text-emerald-500 border-emerald-500/20'
                          )}>
                            {issue.severity} (Sim: {issue.similarity})
                          </Badge>
                        </div>
                        <div className="text-muted-foreground">
                          <span className="font-mono text-xs">{issue.file}:{issue.line_number}</span>
                        </div>
                        <p>{issue.issue}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center text-sm text-muted-foreground mt-4">
                    No semantic issues found. Function intents match implementations.
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}
