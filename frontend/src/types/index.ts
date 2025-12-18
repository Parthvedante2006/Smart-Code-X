export interface User {
  id: string;
  email: string;
  username: string;
  createdAt: string;
  avatar_url?: string;
}

export interface AuthResponse {
  user: User;
  token: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface RegisterCredentials extends LoginCredentials {
  username: string;
}

export type Severity = 'low' | 'medium' | 'high' | 'critical';

export interface CodeIssue {
  id: string;
  file: string;
  line: number;
  column?: number;
  message: string;
  severity: Severity;
  category: 'quality' | 'security' | 'performance' | 'maintainability';
  suggestion?: string;
  code?: string;
}

export interface FileAnalysis {
  path: string;
  issues: CodeIssue[];
  linesOfCode: number;
  complexity: number;
  score: number;
}

// --- Analysis Agent Types ---

export interface SAAIssue {
  file: string;
  line: number;
  message: string;
  severity: Severity; // Mapped to our Severity type
  type: string;
}

export interface SAAResult {
  agent_name: string;
  issues: SAAIssue[];
  total_issues: number;
  file_stats: Record<string, any>;
}

export interface GenericAgentResult {
  agent: string;
  issues: any[];
  summary: any;
  [key: string]: any;
}

export interface IERARecommendation {
  category: string;
  confidence: number;
  description: string;
  files: string[];
  impact: string;
  implementation_example: string;
  effort: string;
  title: string;
}

export interface IERAResult extends GenericAgentResult {
  recommendations: IERARecommendation[];
}

export interface AnalysisResult {
  status: string;
  agents: {
    SAA?: SAAResult;
    SCAA?: GenericAgentResult;
    HDVA?: GenericAgentResult;
    IERA?: IERAResult;
    [key: string]: any;
  };
  errors?: string[];
}

export interface ReviewResult {
  id: string;
  projectName: string; // Often derived from file_name
  file_name?: string; // Real backend field
  createdAt: string;
  overallScore: number; // Calculated on frontend or backend
  totalFiles: number; // Derived or in stats
  totalIssues: number;
  issuesBySeverity: Record<Severity, number>; // Derived
  issuesByCategory: Record<CodeIssue['category'], number>; // Derived
  files: FileAnalysis[]; // Derived from SAA issues mapping
  summary: string;

  // New field for raw backend data
  raw_analysis?: AnalysisResult;
}

export type ReviewStep = 'extracting' | 'analyzing' | 'reviewing' | 'generating';

export interface ReviewProgress {
  step: ReviewStep;
  progress: number;
  message: string;
}
