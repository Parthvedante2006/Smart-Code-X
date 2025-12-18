import { Header } from '@/components/layout/Header';
import {
    Accordion,
    AccordionContent,
    AccordionItem,
    AccordionTrigger,
} from '@/components/ui/accordion';

export default function FAQ() {
    const faqs = [
        {
            question: "Is my code stored securely?",
            answer: "We take security seriously. Your code is processed in a secure environment. We uploaded zip files to a private Firebase Storage bucket and analysis results are stored in Firestore. We do not use your code for training models without explicit consent."
        },
        {
            question: "Is SmartCodeX free to use?",
            answer: "Yes! Currently, SmartCodeX is in beta and completely free to use for personal projects. We may introduce premium tiers for enterprise features in the future."
        },
        {
            question: "Which programming languages are supported?",
            answer: "We primarily support Python, JavaScript/TypeScript, and have experimental support for C++ and Java. The AI agents are capable of understanding a wide range of languages, but tailored static analysis is best for the supported set."
        },
        {
            question: "Is the AI analysis always correct?",
            answer: "While our AI agents (like Semantic Agent and Hallucination Detector) are powerful, they are not infallible. We recommend using the tool as a copilot to catch issues, but always review critical findings yourself."
        },
        {
            question: "Can I analyze private GitHub repositories?",
            answer: "Currently, we only support public GitHub repositories via URL. For private repos, you can download the code as a ZIP and upload it manually."
        }
    ];

    return (
        <div className="min-h-screen bg-background flex flex-col">
            <Header />
            <main className="flex-1 container py-16">
                <div className="max-w-3xl mx-auto">
                    <div className="text-center mb-12">
                        <h1 className="text-4xl font-bold mb-4">Frequently Asked Questions</h1>
                        <p className="text-muted-foreground text-lg">
                            Everything you need to know about SmartCodeX.
                        </p>
                    </div>

                    <Accordion type="single" collapsible className="w-full space-y-4">
                        {faqs.map((faq, index) => (
                            <AccordionItem key={index} value={`item-${index}`} className="border rounded-lg bg-card/50 px-4">
                                <AccordionTrigger className="text-lg font-medium hover:no-underline hover:text-primary transition-colors py-4">
                                    {faq.question}
                                </AccordionTrigger>
                                <AccordionContent className="text-muted-foreground pb-4 text-base leading-relaxed">
                                    {faq.answer}
                                </AccordionContent>
                            </AccordionItem>
                        ))}
                    </Accordion>
                </div>
            </main>
        </div>
    );
}
