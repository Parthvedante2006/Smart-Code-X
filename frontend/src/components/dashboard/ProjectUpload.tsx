import { useState, useCallback } from 'react';
import { useDropzone } from 'react-dropzone';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Upload, Github, FileArchive, Loader2, AlertCircle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface ProjectUploadProps {
  onUpload: (file: File) => void;
  onGithubSubmit: (url: string) => void;
  isLoading: boolean;
}

export function ProjectUpload({ onUpload, onGithubSubmit, isLoading }: ProjectUploadProps) {
  const [githubUrl, setGithubUrl] = useState('');
  const [githubError, setGithubError] = useState('');

  const onDrop = useCallback((acceptedFiles: File[]) => {
    const file = acceptedFiles[0];
    if (file) {
      onUpload(file);
    }
  }, [onUpload]);

  const { getRootProps, getInputProps, isDragActive, fileRejections } = useDropzone({
    onDrop,
    accept: {
      'application/zip': ['.zip'],
      'application/x-zip-compressed': ['.zip'],
    },
    maxFiles: 1,
    maxSize: 50 * 1024 * 1024, // 50MB
    disabled: isLoading,
  });

  const validateGithubUrl = (url: string) => {
    const githubRegex = /^https?:\/\/(www\.)?github\.com\/[\w-]+\/[\w.-]+\/?$/;
    return githubRegex.test(url);
  };

  const handleGithubSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    if (!githubUrl.trim()) {
      setGithubError('Please enter a GitHub URL');
      return;
    }

    if (!validateGithubUrl(githubUrl)) {
      setGithubError('Please enter a valid GitHub repository URL');
      return;
    }

    setGithubError('');
    onGithubSubmit(githubUrl);
  };

  return (
    <Card className="bg-card/50 backdrop-blur-sm border-border/50">
      <CardHeader>
        <CardTitle>Upload Your Project</CardTitle>
        <CardDescription>
          Upload a ZIP file or connect a GitHub repository for analysis
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="upload" className="w-full">
          <TabsList className="grid w-full grid-cols-2">
            <TabsTrigger value="upload" disabled={isLoading}>
              <Upload className="mr-2 h-4 w-4" />
              File Upload
            </TabsTrigger>
            <TabsTrigger value="github" disabled={isLoading}>
              <Github className="mr-2 h-4 w-4" />
              GitHub
            </TabsTrigger>
          </TabsList>

          <TabsContent value="upload" className="mt-6">
            <div
              {...getRootProps()}
              className={cn(
                'relative border-2 border-dashed rounded-xl p-12 text-center cursor-pointer transition-all',
                isDragActive
                  ? 'border-primary bg-primary/5'
                  : 'border-border hover:border-primary/50 hover:bg-muted/50',
                isLoading && 'opacity-50 cursor-not-allowed'
              )}
            >
              <input {...getInputProps()} />
              <div className="flex flex-col items-center gap-4">
                <div className="h-16 w-16 rounded-full bg-primary/10 flex items-center justify-center">
                  {isLoading ? (
                    <Loader2 className="h-8 w-8 text-primary animate-spin" />
                  ) : (
                    <FileArchive className="h-8 w-8 text-primary" />
                  )}
                </div>
                <div>
                  <p className="text-lg font-medium">
                    {isDragActive ? 'Drop your file here' : 'Drag & drop your project'}
                  </p>
                  <p className="text-sm text-muted-foreground mt-1">
                    or click to browse (ZIP files up to 50MB)
                  </p>
                </div>
              </div>
            </div>

            {fileRejections.length > 0 && (
              <div className="flex items-center gap-2 mt-4 p-3 rounded-lg bg-destructive/10 text-destructive text-sm">
                <AlertCircle className="h-4 w-4 flex-shrink-0" />
                <span>Please upload a valid ZIP file (max 50MB)</span>
              </div>
            )}
          </TabsContent>

          <TabsContent value="github" className="mt-6">
            <form onSubmit={handleGithubSubmit} className="space-y-4">
              <div className="space-y-2">
                <div className="relative">
                  <Github className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    type="url"
                    placeholder="https://github.com/username/repository"
                    value={githubUrl}
                    onChange={(e) => {
                      setGithubUrl(e.target.value);
                      setGithubError('');
                    }}
                    className="pl-10"
                    disabled={isLoading}
                  />
                </div>
                {githubError && (
                  <p className="text-sm text-destructive flex items-center gap-1">
                    <AlertCircle className="h-3 w-3" />
                    {githubError}
                  </p>
                )}
              </div>

              <Button
                type="submit"
                className="w-full bg-gradient-primary hover:opacity-90"
                disabled={isLoading}
              >
                {isLoading ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Github className="mr-2 h-4 w-4" />
                    Analyze Repository
                  </>
                )}
              </Button>
            </form>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}
