import { useState, useCallback, useEffect } from 'react';
import { Header } from '@/components/layout/Header';
import { DashboardSidebar } from '@/components/dashboard/DashboardSidebar';
import { ProjectUpload } from '@/components/dashboard/ProjectUpload';
import { ReviewProgressDisplay } from '@/components/dashboard/ReviewProgress';
import { ReviewResults } from '@/components/dashboard/ReviewResults';
import { EmptyState } from '@/components/dashboard/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import { mockApi } from '@/services/mockApi';
import { useToast } from '@/hooks/use-toast';
import type { ReviewResult, ReviewStep } from '@/types';
import { api } from '@/services/api';

type DashboardState = 'idle' | 'uploading' | 'processing' | 'complete';

const REVIEWS_STORAGE_KEY = 'smartcodex_reviews';

export default function Dashboard() {
  const { user } = useAuth();
  const { toast } = useToast();

  const [state, setState] = useState<DashboardState>('idle');
  const [currentStep, setCurrentStep] = useState<ReviewStep>('extracting');
  const [progress, setProgress] = useState(0);
  const [selectedReview, setSelectedReview] = useState<ReviewResult | null>(null);
  const [reviews, setReviews] = useState<ReviewResult[]>([]);
  const [showUpload, setShowUpload] = useState(true);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  // Fetch reviews from backend on mount
  useEffect(() => {
    const fetchReviews = async () => {
      try {
        const data = await api.reviews.list();
        setReviews(data);
      } catch (error) {
        console.error('Failed to fetch reviews:', error);
        toast({
          title: "Error",
          description: "Failed to load reviews",
          variant: "destructive"
        });
      }
    };

    if (user) {
      fetchReviews();
    }
  }, [user, toast]);

  const handleFileUpload = useCallback(async (file: File) => {
    setState('uploading');
    setProgress(0);

    try {
      toast({
        title: 'Uploading project...',
        description: file.name,
      });

      // Fake progress while uploading/processing to keep UI alive
      const interval = setInterval(() => {
        setProgress(old => {
          if (old >= 90) return 90;
          return old + 10;
        });
      }, 500);

      setState('processing');

      // Real API Call
      const reviewResult = await api.reviews.uploadZip(file);

      clearInterval(interval);
      setProgress(100);

      setReviews(prev => [reviewResult, ...prev]);
      setSelectedReview(reviewResult);
      setState('complete');
      setShowUpload(false);

      toast({
        title: 'Analysis complete!',
        description: `Found ${reviewResult.totalIssues} issues across ${reviewResult.totalFiles} files.`,
      });
    } catch (error) {
      setState('idle');
      toast({
        title: 'Upload failed',
        description: error instanceof Error ? error.message : 'Something went wrong',
        variant: 'destructive',
      });
    }
  }, [toast]);

  // GitHub unimplemented in backend for now in the new flow, so we disable or keep mock for now
  // Keeping mock or implementation plan todo
  const handleGithubSubmit = useCallback(async (url: string) => {
    setState('processing');
    setProgress(0);
    setShowUpload(false);

    try {
      toast({
        title: "Analyzing GitHub Repository",
        description: "Downloading and processing repository...",
      });

      // Fake progress
      const interval = setInterval(() => {
        setProgress(old => {
          if (old >= 90) return 90;
          return old + 5;
        });
      }, 800);

      const reviewResult = await api.reviews.analyzeGithub(url);

      clearInterval(interval);
      setProgress(100);

      setReviews(prev => [reviewResult, ...prev]);
      setSelectedReview(reviewResult);
      setState('complete');

      toast({
        title: 'Analysis complete!',
        description: `Found ${reviewResult.totalIssues} issues across ${reviewResult.totalFiles} files.`,
      });

    } catch (error) {
      setState('idle');
      setShowUpload(true);
      toast({
        title: "Analysis Failed",
        description: error instanceof Error ? error.message : "Failed to analyze repository",
        variant: "destructive"
      });
    }
  }, [toast]);

  const handleNewReview = useCallback(() => {
    setState('idle');
    setSelectedReview(null);
    setShowUpload(true);
    setProgress(0);
  }, []);

  const handleSelectReview = useCallback((review: ReviewResult) => {
    setSelectedReview(review);
    setState('complete');
    setShowUpload(false);
  }, []);

  const handleDeleteReview = useCallback(async (id: string) => {
    // Optimistic Update: Remove immediately
    const previousReviews = reviews;
    setReviews(prev => prev.filter(r => r.id !== id));

    // If the deleted review was selected, deselect it immediately
    if (selectedReview?.id === id) {
      setSelectedReview(null);
      setShowUpload(true);
      setState('idle');
    }

    try {
      await api.reviews.delete(id);

      toast({
        title: "Review deleted",
        description: "The review has been permanently deleted."
      });
    } catch (error) {
      // Revert on failure
      setReviews(previousReviews);

      toast({
        title: "Error",
        description: "Failed to delete review",
        variant: "destructive"
      });
    }
  }, [reviews, selectedReview, toast]);

  const isProcessing = state === 'uploading' || state === 'processing';

  return (
    <div className="min-h-screen bg-background flex flex-col">
      <Header />

      <div className="flex flex-1 overflow-hidden">
        <DashboardSidebar
          reviews={reviews}
          selectedReviewId={selectedReview?.id || null}
          onSelectReview={handleSelectReview}
          onNewReview={handleNewReview}
          onDeleteReview={handleDeleteReview}
          isCollapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        />

        <main className="flex-1 overflow-auto">
          <div className="container py-8">
            <div className="mb-8 flex items-end gap-2">
              <div>
                <h1 className="text-3xl font-bold flex items-center gap-2">
                  Welcome back, <span className="text-gradient">{user?.username}</span>
                </h1>
                <p className="text-muted-foreground mt-1">
                  Upload your project to get started with AI-powered code review.
                </p>
              </div>
            </div>

            {showUpload && state === 'idle' && !selectedReview && (
              <div className="max-w-2xl mx-auto">
                <ProjectUpload
                  onUpload={handleFileUpload}
                  onGithubSubmit={handleGithubSubmit}
                  isLoading={isProcessing}
                />
              </div>
            )}

            {isProcessing && (
              <div className="max-w-2xl mx-auto">
                <ReviewProgressDisplay currentStep={currentStep} progress={progress} />
              </div>
            )}

            {state === 'complete' && selectedReview && (
              <ReviewResults result={selectedReview} onNewReview={handleNewReview} />
            )}

            {state === 'idle' && !showUpload && !selectedReview && reviews.length === 0 && (
              <EmptyState onUploadClick={() => setShowUpload(true)} />
            )}
          </div>
        </main>
      </div>
    </div>
  );
}
