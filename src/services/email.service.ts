import { transporter } from "../config/email";
import { renderTemplate } from "../templates/emailTemplate";

export async function sendTemplatedEmail({
    to,
    subject,
    templateName,
    variables,
}: {
    to: string;
    subject: string;
    templateName: string;
    variables: Record<string, string>;
}) {
    try {
        const html = renderTemplate(templateName, variables);

        await transporter.sendMail({
            from: process.env.FROM_EMAIL,
            to,
            subject,
            html,
        });

        console.log(`📧 Email sent to ${to}`);
    } catch (err) {
        console.error("❌ Email send failed:", err);
        throw new Error("Email sending failed");
    }
}
