import { resend } from "../config/email";
import { renderTemplate } from "../templates/emailTemplate";
import { FROM_EMAIL } from "../config/env";
import fs from "fs";
import path from "path";
import { apiError } from "../utils/apiError";

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

        // Attach the logo as an inline CID attachment so email clients display it
        // without requiring a large base64 inline data URI (prevents Gmail clipping).
        const logoPath = path.join(__dirname, "../../public/fullLogo.png");

        const logoContent = fs.readFileSync(logoPath).toString("base64");

        const { error } = await resend.emails.send({
            from: FROM_EMAIL ?? "",
            to: [to],
            subject,
            html,
            attachments: [
                {
                    filename: "fullLogo.png",
                    content: logoContent,
                    contentId: "fullLogo",
                },
            ],
        });

        if (error) {
            throw error;
        }
    } catch (err) {
        console.error("Error sending email:", err);
        throw new apiError(500, 'Failed to send email');
    }
}
