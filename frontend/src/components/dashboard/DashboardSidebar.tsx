import { format } from 'date-fns';
import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import {
  Code2,
  Plus,
  FileCode,
  Clock,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  Trash2,
} from 'lucide-react';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import type { ReviewResult } from '@/types';
import { cn } from '@/lib/utils';

interface DashboardSidebarProps {
  reviews: ReviewResult[];
  selectedReviewId: string | null;
  onSelectReview: (review: ReviewResult) => void;
  onNewReview: () => void;
  onDeleteReview: (id: string) => void;
  isCollapsed: boolean;
  onToggleCollapse: () => void;
}

export function DashboardSidebar({
  reviews,
  selectedReviewId,
  onSelectReview,
  onNewReview,
  onDeleteReview,
  isCollapsed,
  onToggleCollapse,
}: DashboardSidebarProps) {
  const [reviewToDelete, setReviewToDelete] = useState<string | null>(null);

  const getScoreColor = (score: number) => {
    if (score >= 80) return 'text-success';
    if (score >= 60) return 'text-warning';
    return 'text-destructive';
  };

  return (
    <aside
      className={cn(
        'relative flex flex-col border-r border-border bg-card transition-[width] duration-300 ease-in-out overflow-hidden will-change-[width]',
        isCollapsed ? 'w-[70px]' : 'w-72'
      )}
    >

      {/* Header - Click to Toggle */}
      <div
        className={cn(
          "flex h-16 items-center border-b border-border px-4 transition-colors hover:bg-muted/50 cursor-pointer",
          isCollapsed && "justify-center px-0"
        )}
        onClick={onToggleCollapse}
        title={isCollapsed ? "Expand Sidebar" : "Collapse Sidebar"}
      >
        <div className="flex items-center gap-2 text-primary">
          <Code2 className="h-6 w-6" />
          {!isCollapsed && <span className="font-semibold text-foreground">Reviews</span>}
        </div>
      </div>

      {/* New Review Button */}
      <div className="p-3">
        <Button
          onClick={onNewReview}
          className={cn(
            'bg-gradient-primary hover:opacity-90 shadow-md transition-all duration-300',
            isCollapsed ? 'w-10 h-10 p-0 rounded-full mx-auto' : 'w-full'
          )}
        >
          <Plus className="h-5 w-5" />
          {!isCollapsed && <span className="ml-2 font-medium">New Review</span>}
        </Button>
      </div>

      {/* Reviews List */}
      <ScrollArea className="flex-1">
        <div className={cn("space-y-2 pb-4", isCollapsed ? "px-2" : "px-3")}>
          {reviews.length === 0 ? (
            <div className={cn('text-center py-8', isCollapsed && 'hidden')}>
              <FileCode className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground">No reviews yet</p>
            </div>
          ) : (
            reviews.map((review) => (
              <button
                key={review.id}
                onClick={() => onSelectReview(review)}
                className={cn(
                  'rounded-lg border border-transparent text-left transition-all hover:bg-muted/50 relative group outline-none focus-visible:ring-2 focus-visible:ring-ring',
                  selectedReviewId === review.id && 'bg-muted/80 border-border shadow-sm',
                  isCollapsed
                    ? 'w-10 h-10 p-0 flex items-center justify-center mx-auto'
                    : 'w-full p-3'
                )}
              >
                {isCollapsed ? (
                  <div
                    className={cn(
                      'h-8 w-8 rounded-full flex items-center justify-center text-xs font-bold border',
                      getScoreColor(review.overallScore),
                      'bg-background border-border shadow-sm'
                    )}
                  >
                    {review.overallScore}
                  </div>
                ) : (
                  <div className="w-full">
                    <div className="flex items-start justify-between gap-2 mb-2">
                      <div className="flex-1 min-w-0">
                        <p className="font-medium truncate">{review.projectName}</p>
                        <div className="flex items-center gap-2 mt-1 text-xs text-muted-foreground">
                          <Clock className="h-3 w-3" />
                          {format(new Date(review.createdAt), 'MMM d, yyyy')}
                        </div>
                      </div>
                      <div className="flex flex-col items-end gap-2">
                        <div
                          className={cn(
                            'text-lg font-bold',
                            getScoreColor(review.overallScore)
                          )}
                        >
                          {review.overallScore}
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 text-muted-foreground hover:text-destructive"
                          onClick={(e) => {
                            e.stopPropagation();
                            setReviewToDelete(review.id);
                          }}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                    <div className="flex items-center gap-3 mt-2 text-xs">
                      <span className="text-muted-foreground">
                        {review.totalFiles} files
                      </span>
                      {review.totalIssues > 0 && (
                        <span className="flex items-center gap-1 text-warning">
                          <AlertTriangle className="h-3 w-3" />
                          {review.totalIssues} issues
                        </span>
                      )}
                    </div>
                  </div>
                )}
              </button>
            ))
          )}
        </div>
      </ScrollArea>

      <AlertDialog open={!!reviewToDelete} onOpenChange={(open) => !open && setReviewToDelete(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete this code review from your history.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              onClick={() => {
                if (reviewToDelete) {
                  onDeleteReview(reviewToDelete);
                  setReviewToDelete(null);
                }
              }}
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </aside >
  );
}
