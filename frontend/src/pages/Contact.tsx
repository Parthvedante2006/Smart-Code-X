import { Header } from '@/components/layout/Header';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Mail, Github, Linkedin, ExternalLink } from 'lucide-react';

export default function Contact() {
    return (
        <div className="min-h-screen bg-background flex flex-col">
            <Header />
            <main className="flex-1 container py-16 flex items-center justify-center">
                <div className="w-full max-w-xl">
                    <div className="text-center mb-8">
                        <h1 className="text-4xl font-bold mb-4">Get in Touch</h1>
                        <p className="text-muted-foreground text-lg">
                            Have questions or want to collaborate? Reach out to us through any of these channels.
                        </p>
                    </div>

                    <div className="grid gap-6">
                        <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-colors">
                            <CardContent className="p-6 flex items-center gap-4">
                                <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                                    <Mail className="h-6 w-6" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="font-semibold text-lg">Email Us</h3>
                                    <p className="text-muted-foreground">support@smartcodex.com</p>
                                </div>
                                <Button variant="ghost" size="icon" asChild>
                                    <a href="mailto:support@smartcodex.com">
                                        <ExternalLink className="h-4 w-4" />
                                    </a>
                                </Button>
                            </CardContent>
                        </Card>

                        <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-colors">
                            <CardContent className="p-6 flex items-center gap-4">
                                <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                                    <Github className="h-6 w-6" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="font-semibold text-lg">GitHub</h3>
                                    <p className="text-muted-foreground">/Smart-Code-X</p>
                                </div>
                                <Button variant="ghost" size="icon" asChild>
                                    <a href="https://github.com/Parthvedante2006/Smart-Code-X" target="_blank" rel="noopener noreferrer">
                                        <ExternalLink className="h-4 w-4" />
                                    </a>
                                </Button>
                            </CardContent>
                        </Card>

                        <Card className="bg-card/50 backdrop-blur-sm border-border/50 hover:border-primary/50 transition-colors">
                            <CardContent className="p-6 flex items-center gap-4">
                                <div className="h-12 w-12 rounded-full bg-primary/10 flex items-center justify-center text-primary">
                                    <Linkedin className="h-6 w-6" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="font-semibold text-lg">LinkedIn</h3>
                                    <p className="text-muted-foreground">Connect with the developer</p>
                                </div>
                                <Button variant="ghost" size="icon" asChild>
                                    <a href="#" target="_blank" rel="noopener noreferrer">
                                        <ExternalLink className="h-4 w-4" />
                                    </a>
                                </Button>
                            </CardContent>
                        </Card>
                    </div>
                </div>
            </main>
        </div>
    );
}
