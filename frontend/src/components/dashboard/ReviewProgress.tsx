import { useEffect, useState } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Progress } from '@/components/ui/progress';
import { FileSearch, Code2, Shield, FileText, CheckCircle2, Loader2 } from 'lucide-react';
import type { ReviewStep, ReviewProgress } from '@/types';
import { cn } from '@/lib/utils';

interface ReviewProgressDisplayProps {
  currentStep: ReviewStep;
  progress: number;
}

const steps: { key: ReviewStep; label: string; icon: typeof FileSearch }[] = [
  { key: 'extracting', label: 'Extracting Files', icon: FileSearch },
  { key: 'analyzing', label: 'Analyzing Code', icon: Code2 },
  { key: 'reviewing', label: 'Security Review', icon: Shield },
  { key: 'generating', label: 'Generating Report', icon: FileText },
];

export function ReviewProgressDisplay({ currentStep, progress }: ReviewProgressDisplayProps) {
  const currentStepIndex = steps.findIndex(s => s.key === currentStep);

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Loader2 className="h-5 w-5 animate-spin text-primary" />
          Analyzing Your Code
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-8">
        {/* Overall Progress */}
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Overall Progress</span>
            <span className="font-medium">{Math.round(progress)}%</span>
          </div>
          <Progress value={progress} className="h-2" />
        </div>

        {/* Steps */}
        <div className="space-y-4">
          {steps.map((step, index) => {
            const isCompleted = index < currentStepIndex;
            const isCurrent = index === currentStepIndex;
            const isPending = index > currentStepIndex;

            return (
              <div
                key={step.key}
                className={cn(
                  'flex items-center gap-4 p-4 rounded-lg border transition-all',
                  isCompleted && 'bg-success/10 border-success/30',
                  isCurrent && 'bg-primary/10 border-primary/30 animate-pulse',
                  isPending && 'bg-muted/30 border-border opacity-50'
                )}
              >
                <div
                  className={cn(
                    'h-10 w-10 rounded-full flex items-center justify-center',
                    isCompleted && 'bg-success text-success-foreground',
                    isCurrent && 'bg-primary text-primary-foreground',
                    isPending && 'bg-muted text-muted-foreground'
                  )}
                >
                  {isCompleted ? (
                    <CheckCircle2 className="h-5 w-5" />
                  ) : isCurrent ? (
                    <Loader2 className="h-5 w-5 animate-spin" />
                  ) : (
                    <step.icon className="h-5 w-5" />
                  )}
                </div>
                <div className="flex-1">
                  <p className={cn(
                    'font-medium',
                    isCompleted && 'text-success',
                    isCurrent && 'text-primary',
                    isPending && 'text-muted-foreground'
                  )}>
                    {step.label}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {isCompleted && 'Completed'}
                    {isCurrent && 'In progress...'}
                    {isPending && 'Waiting'}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
