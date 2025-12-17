import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Header } from '@/components/layout/Header';
import {
  Code2,
  Shield,
  Zap,
  GitBranch,
  FileCode,
  BarChart3,
  ArrowRight,
  CheckCircle2,
  Star,
} from 'lucide-react';

const features = [
  {
    icon: Shield,
    title: 'Security Analysis',
    description: 'Detect vulnerabilities, SQL injections, and security misconfigurations before they become problems.',
  },
  {
    icon: Zap,
    title: 'Performance Insights',
    description: 'Identify bottlenecks, memory leaks, and inefficient patterns that slow down your application.',
  },
  {
    icon: FileCode,
    title: 'Code Quality',
    description: 'Get actionable feedback on code style, best practices, and maintainability improvements.',
  },
  {
    icon: GitBranch,
    title: 'GitHub Integration',
    description: 'Connect your repositories directly or upload project files for instant analysis.',
  },
  {
    icon: BarChart3,
    title: 'Detailed Reports',
    description: 'Comprehensive reports with severity ratings, file-by-file breakdown, and fix suggestions.',
  },
  {
    icon: Code2,
    title: 'Multi-Language Support',
    description: 'Support for JavaScript, TypeScript, Python, Java, Go, and many more languages.',
  },
];

const stats = [
  { value: '10M+', label: 'Lines Reviewed' },
  { value: '50K+', label: 'Issues Found' },
  { value: '99.9%', label: 'Uptime' },
  { value: '< 2min', label: 'Avg Analysis' },
];

export default function Landing() {
  return (
    <div className="min-h-screen bg-background">
      <Header />

      {/* Hero Section */}
      <section className="relative overflow-hidden pt-20 pb-32">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-primary/10 rounded-full blur-[120px]" />
        </div>

        <div className="container relative">
          <div className="flex flex-col items-center text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-8 animate-fade-in">
              <Star className="h-4 w-4 fill-primary" />
              AI-Powered Code Review Platform
            </div>

            <h1 className="text-5xl md:text-7xl font-bold tracking-tight mb-6 animate-slide-up">
              Ship Better Code,{' '}
              <span className="text-gradient">Faster</span>
            </h1>

            <p className="text-xl text-muted-foreground mb-10 max-w-2xl animate-slide-up" style={{ animationDelay: '0.1s' }}>
              SmartCodeX uses advanced AI to analyze your codebase, catch bugs,
              identify security vulnerabilities, and suggest improvements —
              all in seconds, not hours.
            </p>

            <div className="flex flex-col sm:flex-row gap-4 animate-slide-up" style={{ animationDelay: '0.2s' }}>
              <Button size="lg" asChild className="bg-gradient-primary hover:opacity-90 h-12 px-8 text-lg glow-primary-sm">
                <Link to="/auth?mode=register">
                  Start Free Trial
                  <ArrowRight className="ml-2 h-5 w-5" />
                </Link>
              </Button>
              <Button size="lg" variant="outline" asChild className="h-12 px-8 text-lg">
                <Link to="/auth">View Demo</Link>
              </Button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mt-20 w-full animate-fade-in" style={{ animationDelay: '0.3s' }}>
              {stats.map((stat) => (
                <div key={stat.label} className="text-center">
                  <div className="text-3xl md:text-4xl font-bold text-gradient">{stat.value}</div>
                  <div className="text-sm text-muted-foreground mt-1">{stat.label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-24 bg-muted/30">
        <div className="container">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              Everything You Need for Code Excellence
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Comprehensive analysis tools designed for modern development teams.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
            {features.map((feature) => (
              <div
                key={feature.title}
                className="group p-6 rounded-xl bg-card border border-border/50 hover:border-primary/50 transition-all hover:shadow-lg hover:shadow-primary/5"
              >
                <div className="h-12 w-12 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-primary/20 transition-colors">
                  <feature.icon className="h-6 w-6 text-primary" />
                </div>
                <h3 className="text-xl font-semibold mb-2">{feature.title}</h3>
                <p className="text-muted-foreground">{feature.description}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-24">
        <div className="container">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">
              How It Works
            </h2>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
              Get your code reviewed in three simple steps.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8 max-w-4xl mx-auto">
            {[
              { step: '01', title: 'Upload Your Code', description: 'Drag and drop your project files or connect your GitHub repository.' },
              { step: '02', title: 'AI Analysis', description: 'Our AI engine analyzes your code for issues, vulnerabilities, and improvements.' },
              { step: '03', title: 'Get Results', description: 'Review detailed reports with actionable insights and fix suggestions.' },
            ].map((item, index) => (
              <div key={item.step} className="relative">
                <div className="text-6xl font-bold text-primary/10 mb-4">{item.step}</div>
                <h3 className="text-xl font-semibold mb-2">{item.title}</h3>
                <p className="text-muted-foreground">{item.description}</p>
                {index < 2 && (
                  <div className="hidden md:block absolute top-8 right-0 translate-x-1/2 w-8 h-px bg-border" />
                )}
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-24 bg-muted/30">
        <div className="container">
          <div className="relative rounded-2xl bg-gradient-primary p-12 md:p-16 overflow-hidden">
            <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iNjAiIGhlaWdodD0iNjAiIHZpZXdCb3g9IjAgMCA2MCA2MCIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj48ZyBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPjxnIGZpbGw9IiNmZmYiIGZpbGwtb3BhY2l0eT0iMC4xIj48cGF0aCBkPSJNMzYgMzRoLTJ2LTRoMnY0em0wLTZoLTJ2LTRoMnY0em0wLTZoLTJ2LTRoMnY0em0wLTZoLTJWOGgydjh6bTAgMjRoLTJ2LTRoMnY0em0wIDZoLTJ2LTRoMnY0em0wIDZoLTJ2LTRoMnY0eiIvPjwvZz48L2c+PC9zdmc+')] opacity-20" />
            <div className="relative text-center text-white">
              <h2 className="text-3xl md:text-4xl font-bold mb-4">
                Ready to Improve Your Code Quality?
              </h2>
              <p className="text-lg opacity-90 mb-8 max-w-2xl mx-auto">
                Join thousands of developers who trust SmartCodeX for their code reviews.
                Start your free trial today.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Button size="lg" variant="secondary" asChild className="h-12 px-8">
                  <Link to="/auth?mode=register">
                    Get Started Free
                    <ArrowRight className="ml-2 h-5 w-5" />
                  </Link>
                </Button>
              </div>
              <div className="flex items-center justify-center gap-6 mt-8 text-sm opacity-80">
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4" />
                  No credit card required
                </span>
                <span className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4" />
                  14-day free trial
                </span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-border">
        <div className="container">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Code2 className="h-6 w-6 text-primary" />
              <span className="font-semibold">SmartCodeX</span>
            </div>
            <p className="text-sm text-muted-foreground">
              © {new Date().getFullYear()} SmartCodeX. All rights reserved.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}
