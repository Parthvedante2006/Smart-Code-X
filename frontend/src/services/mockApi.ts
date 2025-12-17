import type { User, AuthResponse, LoginCredentials, RegisterCredentials, ReviewResult, CodeIssue, FileAnalysis, Severity } from '@/types';

const delay = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

const generateId = () => Math.random().toString(36).substring(2, 15);

// Mock user database
const users: Map<string, { user: User; password: string }> = new Map();

// Mock token storage
const tokens: Map<string, User> = new Map();

export const mockApi = {
  auth: {
    async register(credentials: RegisterCredentials): Promise<AuthResponse> {
      await delay(800);

      if (users.has(credentials.email)) {
        throw new Error('User already exists with this email');
      }

      if (credentials.password.length < 8) {
        throw new Error('Password must be at least 8 characters');
      }

      const user: User = {
        id: generateId(),
        email: credentials.email,
        username: credentials.username,
        createdAt: new Date().toISOString(),
      };

      users.set(credentials.email, { user, password: credentials.password });

      const token = generateId() + generateId();
      tokens.set(token, user);

      return { user, token };
    },

    async login(credentials: LoginCredentials): Promise<AuthResponse> {
      await delay(800);

      const userData = users.get(credentials.email);

      if (!userData || userData.password !== credentials.password) {
        throw new Error('Invalid email or password');
      }

      const token = generateId() + generateId();
      tokens.set(token, userData.user);

      return { user: userData.user, token };
    },

    async logout(token: string): Promise<void> {
      await delay(300);
      tokens.delete(token);
    },

    async me(token: string): Promise<User> {
      await delay(300);

      const user = tokens.get(token);

      if (!user) {
        throw new Error('Invalid or expired token');
      }

      return user;
    },
  },

  review: {
    async upload(file: File, onProgress: (progress: number) => void): Promise<ReviewResult> {
      // Simulate upload progress
      for (let i = 0; i <= 100; i += 10) {
        await delay(100);
        onProgress(i);
      }

      return generateMockReviewResult(file.name.replace('.zip', ''));
    },

    async github(url: string): Promise<ReviewResult> {
      await delay(500);

      const repoName = url.split('/').pop() || 'repository';
      return generateMockReviewResult(repoName);
    },
  },
};

function generateMockReviewResult(projectName: string): ReviewResult {
  const severities: Severity[] = ['low', 'medium', 'high', 'critical'];
  const categories: CodeIssue['category'][] = ['quality', 'security', 'performance', 'maintainability'];

  const mockIssues: Omit<CodeIssue, 'id' | 'file' | 'line'>[] = [
    { message: 'Unused variable detected', severity: 'low', category: 'quality', suggestion: 'Remove or use the variable', code: 'const unused = 42;' },
    { message: 'Potential SQL injection vulnerability', severity: 'critical', category: 'security', suggestion: 'Use parameterized queries', code: 'query(`SELECT * FROM users WHERE id = ${userId}`)' },
    { message: 'Function complexity exceeds threshold', severity: 'medium', category: 'maintainability', suggestion: 'Break down into smaller functions' },
    { message: 'Missing error handling', severity: 'high', category: 'quality', suggestion: 'Add try-catch block', code: 'await fetchData()' },
    { message: 'Inefficient loop detected', severity: 'medium', category: 'performance', suggestion: 'Consider using Array methods' },
    { message: 'Hardcoded API key found', severity: 'critical', category: 'security', suggestion: 'Move to environment variables', code: 'const API_KEY = "sk-123..."' },
    { message: 'Missing input validation', severity: 'high', category: 'security', suggestion: 'Validate user input before processing' },
    { message: 'Deprecated function usage', severity: 'low', category: 'maintainability', suggestion: 'Update to newer API' },
    { message: 'Memory leak potential', severity: 'high', category: 'performance', suggestion: 'Clean up subscriptions in useEffect' },
    { message: 'Magic number detected', severity: 'low', category: 'quality', suggestion: 'Extract to named constant', code: 'if (status === 200)' },
  ];

  const fileNames = [
    'src/index.ts',
    'src/components/App.tsx',
    'src/utils/helpers.ts',
    'src/api/client.ts',
    'src/hooks/useAuth.ts',
    'src/services/database.ts',
    'src/middleware/auth.ts',
    'src/config/settings.ts',
  ];

  const files: FileAnalysis[] = fileNames.map(path => {
    const fileIssues: CodeIssue[] = mockIssues
      .slice(0, Math.floor(Math.random() * 4) + 1)
      .map(issue => ({
        ...issue,
        id: generateId(),
        file: path,
        line: Math.floor(Math.random() * 200) + 1,
        column: Math.floor(Math.random() * 80) + 1,
      }));

    return {
      path,
      issues: fileIssues,
      linesOfCode: Math.floor(Math.random() * 300) + 50,
      complexity: Math.floor(Math.random() * 20) + 1,
      score: Math.floor(Math.random() * 40) + 60,
    };
  });

  const allIssues = files.flatMap(f => f.issues);

  const issuesBySeverity = severities.reduce((acc, sev) => {
    acc[sev] = allIssues.filter(i => i.severity === sev).length;
    return acc;
  }, {} as Record<Severity, number>);

  const issuesByCategory = categories.reduce((acc, cat) => {
    acc[cat] = allIssues.filter(i => i.category === cat).length;
    return acc;
  }, {} as Record<CodeIssue['category'], number>);

  const overallScore = Math.floor(
    files.reduce((sum, f) => sum + f.score, 0) / files.length
  );

  return {
    id: generateId(),
    projectName,
    createdAt: new Date().toISOString(),
    overallScore,
    totalFiles: files.length,
    totalIssues: allIssues.length,
    issuesBySeverity,
    issuesByCategory,
    files,
    summary: `Analysis of ${projectName} revealed ${allIssues.length} issues across ${files.length} files. ${issuesBySeverity.critical} critical and ${issuesBySeverity.high} high severity issues require immediate attention. Focus on addressing security vulnerabilities and improving code quality for better maintainability.`,
  };
}
