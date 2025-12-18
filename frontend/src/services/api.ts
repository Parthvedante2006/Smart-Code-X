
import type { ReviewResult, Severity, CodeIssue, FileAnalysis, AnalysisResult, SAAIssue, SAAResult } from '@/types';

// Backend URL from environment or default to localhost
export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const getAuthHeader = () => {
    const token = localStorage.getItem('smartcodex_token');
    return token ? { 'Authorization': `Bearer ${token}` } : {};
};

// Helper: Map Backend SAA Issues to Frontend CodeIssue
const mapIssues = (saaIssues: SAAIssue[] = []): CodeIssue[] => {
    return saaIssues.map((issue, index) => ({
        id: `issue-${index}-${Date.now()}`,
        file: issue.file,
        line: issue.line,
        message: issue.message,
        severity: issue.severity.toLowerCase() as Severity,
        category: (issue.type.includes('security') ? 'security' : 'quality') as CodeIssue['category'], // Simple mapping
        code: '', // Backend might not provide snippet line yet
        suggestion: '',
    }));
};

// Helper: Convert Raw Analysis to Frontend ReviewResult
const transformAnalysisToReview = (backendData: any): ReviewResult => {
    // backendData is the Firestore document + raw_analysis
    const raw: AnalysisResult | undefined = backendData.raw_analysis;
    const saa: SAAResult | undefined = raw?.agents?.SAA;

    const allIssues = mapIssues(saa?.issues || []);

    // Group by file
    const filesMap = new Map<string, CodeIssue[]>();
    allIssues.forEach(i => {
        if (!filesMap.has(i.file)) filesMap.set(i.file, []);
        filesMap.get(i.file)?.push(i);
    });

    const files: FileAnalysis[] = Array.from(filesMap.entries()).map(([path, issues]) => ({
        path,
        issues,
        linesOfCode: 0, // Placeholder
        complexity: 0, // Placeholder
        score: 100 - (issues.length * 5), // Simple calc
    }));

    // Stats
    const issuesBySeverity: Record<Severity, number> = {
        low: 0, medium: 0, high: 0, critical: 0
    };
    allIssues.forEach(i => {
        if (issuesBySeverity[i.severity] !== undefined) {
            issuesBySeverity[i.severity]++;
        }
    });

    const issuesByCategory: Record<CodeIssue['category'], number> = {
        quality: 0, security: 0, performance: 0, maintainability: 0
    };
    allIssues.forEach(i => {
        if (issuesByCategory[i.category] !== undefined) {
            issuesByCategory[i.category]++;
        }
    });

    // Weighted Score Calculation
    let deduction = 0;
    allIssues.forEach(issue => {
        switch (issue.severity) {
            case 'critical': deduction += 10; break;
            case 'high': deduction += 5; break;
            case 'medium': deduction += 2; break;
            case 'low': deduction += 1; break;
            default: deduction += 1; // Default to low if unknown
        }
    });

    const overallScore = Math.max(0, 100 - deduction);

    return {
        id: backendData.id || `temp-${Date.now()}`,
        projectName: backendData.file_name || 'Project',
        file_name: backendData.file_name,
        createdAt: backendData.created_at || new Date().toISOString(),
        overallScore,
        totalFiles: files.length,
        totalIssues: allIssues.length,
        issuesBySeverity,
        issuesByCategory,
        files,
        summary: `Analysis completed. Found ${allIssues.length} issues.`,
        raw_analysis: raw
    };
};

export const api = {
    reviews: {
        async list(): Promise<ReviewResult[]> {
            const response = await fetch(`${API_BASE_URL}/reviews`, {
                headers: getAuthHeader(),
            });
            if (!response.ok) throw new Error('Failed to fetch reviews');
            const data = await response.json();
            // Transform each item
            return data.map(transformAnalysisToReview);
        },

        async uploadZip(file: File): Promise<ReviewResult> {
            const formData = new FormData();
            formData.append('file', file);

            // Note: This matches the endpoint we just created
            const response = await fetch(`${API_BASE_URL}/analyze/upload-zip`, {
                method: 'POST',
                headers: {
                    ...getAuthHeader(),
                },
                body: formData,
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || 'Upload failed');
            }

            const data = await response.json();
            return transformAnalysisToReview(data);
        },

        async analyzeGithub(url: string): Promise<ReviewResult> {
            const response = await fetch(`${API_BASE_URL}/analyze/github`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeader(),
                },
                body: JSON.stringify({ url }),
            });

            if (!response.ok) {
                const err = await response.json();
                throw new Error(err.detail || 'Analysis failed');
            }

            const data = await response.json();
            return transformAnalysisToReview(data);
        },

        async delete(id: string): Promise<void> {
            const response = await fetch(`${API_BASE_URL}/reviews/${id}`, {
                method: 'DELETE',
                headers: getAuthHeader(),
            });
            if (!response.ok) throw new Error('Failed to delete review');
        },
    },

    feedback: {
        async submit(data: { name?: string; email?: string; type: string; message: string }): Promise<void> {
            const response = await fetch(`${API_BASE_URL}/feedback`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    // Optional auth header if we want to track it, but endpoint is open
                    ...getAuthHeader(),
                },
                body: JSON.stringify({
                    feedback_type: data.type,
                    message: data.message,
                    name: data.name,
                    email: data.email
                }),
            });
            if (!response.ok) throw new Error('Failed to submit feedback');
        }
    }
};
