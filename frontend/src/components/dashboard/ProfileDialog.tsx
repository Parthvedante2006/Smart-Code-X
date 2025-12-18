import { useState, useRef, useEffect } from 'react';
import { API_BASE_URL } from '@/services/api';
import { useAuth } from '@/contexts/AuthContext';
import { Button } from '@/components/ui/button';
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
} from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar';
import { useToast } from '@/hooks/use-toast';
import { Loader2, Upload, User } from 'lucide-react';

interface ProfileDialogProps {
    open: boolean;
    onOpenChange: (open: boolean) => void;
}

export function ProfileDialog({ open, onOpenChange }: ProfileDialogProps) {
    const { user, updateUser } = useAuth();
    const { toast } = useToast();
    const [username, setUsername] = useState(user?.username || '');
    const [isLoading, setIsLoading] = useState(false);
    const fileInputRef = useRef<HTMLInputElement>(null);

    // Reset username when dialog opens
    useEffect(() => {
        if (open && user?.username) {
            setUsername(user.username);
        }
    }, [open, user]);

    const handleFileSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
        const file = e.target.files?.[0];
        if (!file) return;

        // Validate file type
        if (!file.type.startsWith('image/')) {
            toast({
                title: "Invalid file type",
                description: "Please upload an image file.",
                variant: "destructive"
            });
            return;
        }

        // Upload immediately
        setIsLoading(true);
        const formData = new FormData();
        formData.append('file', file);

        try {
            const token = localStorage.getItem('smartcodex_token');
            const response = await fetch(`${API_BASE_URL}/auth/avatar`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`
                },
                body: formData,
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Failed to upload avatar');
            }

            const data = await response.json();
            updateUser({ avatar_url: data.avatar_url });
            toast({
                title: "Avatar updated",
                description: "Your profile picture has been updated."
            });
        } catch (error) {
            toast({
                title: "Error",
                description: "Failed to upload avatar.",
                variant: "destructive"
            });
        } finally {
            setIsLoading(false);
        }
    };

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!username.trim()) return;

        setIsLoading(true);
        try {
            const token = localStorage.getItem('smartcodex_token');
            const response = await fetch(`${API_BASE_URL}/auth/profile`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify({ username }),
            });

            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Failed to update profile');
            }

            const updatedUser = await response.json();
            updateUser({ username: updatedUser.username });

            toast({
                title: 'Profile updated',
                description: 'Your changes have been saved successfully.',
            });
            onOpenChange(false);
        } catch (error) {
            toast({
                title: 'Error',
                description: error instanceof Error ? error.message : 'Something went wrong',
                variant: 'destructive',
            });
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <Dialog open={open} onOpenChange={onOpenChange}>
            <DialogContent className="sm:max-w-[425px]">
                <DialogHeader>
                    <DialogTitle>Edit profile</DialogTitle>
                    <DialogDescription>
                        Make changes to your profile here. Click save when you're done.
                    </DialogDescription>
                </DialogHeader>

                <div className="flex flex-col items-center gap-4 py-4">
                    <div className="relative group cursor-pointer" onClick={() => fileInputRef.current?.click()}>
                        <Avatar className="h-24 w-24">
                            <AvatarImage src={user?.avatar_url || ''} />
                            <AvatarFallback className="text-2xl bg-primary/10 text-primary">
                                {user?.username?.charAt(0).toUpperCase()}
                            </AvatarFallback>
                        </Avatar>
                        <div className="absolute inset-0 bg-black/40 rounded-full flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                            <Upload className="h-6 w-6 text-white" />
                        </div>
                    </div>
                    <input
                        type="file"
                        ref={fileInputRef}
                        className="hidden"
                        accept="image/*"
                        onChange={handleFileSelect}
                    />
                    <p className="text-xs text-muted-foreground">Click to upload new avatar</p>
                </div>

                <form onSubmit={handleSubmit}>
                    <div className="grid gap-4 py-4">
                        <div className="grid grid-cols-4 items-center gap-4">
                            <Label htmlFor="username" className="text-right">
                                Username
                            </Label>
                            <Input
                                id="username"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="col-span-3"
                            />
                        </div>
                    </div>
                    <DialogFooter>
                        <Button type="submit" disabled={isLoading}>
                            {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                            Save changes
                        </Button>
                    </DialogFooter>
                </form>
            </DialogContent>
        </Dialog>
    );
}
