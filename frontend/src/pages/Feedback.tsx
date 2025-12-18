import { useState } from 'react';
import { useForm } from 'react-hook-form';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';
import { api } from '@/services/api';
import { Loader2, MessageSquare, Send } from 'lucide-react';
import { Header } from '@/components/layout/Header';

interface FeedbackFormData {
    name: string;
    email: string;
    type: string;
    message: string;
}

export default function Feedback() {
    const { register, handleSubmit, reset, setValue, formState: { errors } } = useForm<FeedbackFormData>({
        defaultValues: { type: 'general' }
    });
    const [isSubmitting, setIsSubmitting] = useState(false);
    const { toast } = useToast();

    const onSubmit = async (data: FeedbackFormData) => {
        setIsSubmitting(true);
        try {
            await api.feedback.submit(data);
            toast({
                title: "Feedback Submitted",
                description: "Thank you for your feedback! We appreciate your input.",
            });
            reset();
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to submit feedback. Please try again.",
                variant: "destructive"
            });
        } finally {
            setIsSubmitting(false);
        }
    };

    return (
        <div className="min-h-screen bg-background flex flex-col">
            <Header />
            <main className="flex-1 container py-12 flex items-center justify-center">
                <div className="w-full max-w-lg">
                    <Card className="border-border/50 bg-card/50 backdrop-blur-sm">
                        <CardHeader>
                            <CardTitle className="flex items-center gap-2">
                                <MessageSquare className="h-6 w-6 text-primary" />
                                Send Feedback
                            </CardTitle>
                            <CardDescription>
                                We'd love to hear from you! Report bugs, suggest features, or just say hi.
                            </CardDescription>
                        </CardHeader>
                        <CardContent>
                            <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">

                                <div className="grid grid-cols-2 gap-4">
                                    <div className="space-y-2">
                                        <Label htmlFor="name">Name (Optional)</Label>
                                        <Input id="name" placeholder="John Doe" {...register('name')} />
                                    </div>
                                    <div className="space-y-2">
                                        <Label htmlFor="email">Email (Optional)</Label>
                                        <Input id="email" type="email" placeholder="john@example.com" {...register('email')} />
                                    </div>
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="type">Feedback Type</Label>
                                    <Select onValueChange={(val) => setValue('type', val)} defaultValue="general">
                                        <SelectTrigger>
                                            <SelectValue placeholder="Select type" />
                                        </SelectTrigger>
                                        <SelectContent>
                                            <SelectItem value="general">General</SelectItem>
                                            <SelectItem value="suggestion">Suggestion</SelectItem>
                                            <SelectItem value="bug">Bug Report</SelectItem>
                                        </SelectContent>
                                    </Select>
                                </div>

                                <div className="space-y-2">
                                    <Label htmlFor="message">Message</Label>
                                    <Textarea
                                        id="message"
                                        placeholder="Tell us what you think..."
                                        className="min-h-[120px]"
                                        {...register('message', { required: true })}
                                    />
                                    {errors.message && <span className="text-xs text-destructive">Message is required</span>}
                                </div>

                                <Button type="submit" className="w-full bg-gradient-primary" disabled={isSubmitting}>
                                    {isSubmitting ? (
                                        <>
                                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                                            Sending...
                                        </>
                                    ) : (
                                        <>
                                            <Send className="mr-2 h-4 w-4" />
                                            Submit Feedback
                                        </>
                                    )}
                                </Button>
                            </form>
                        </CardContent>
                    </Card>
                </div>
            </main>
        </div>
    );
}
