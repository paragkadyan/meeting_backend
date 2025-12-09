import { transporter } from "../config/email";
import { renderTemplate } from "../templates/emailTemplate";
import { FROM_EMAIL } from "../config/env";
import path from "path";

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

        await transporter.sendMail({
            from: FROM_EMAIL,
            to,
            subject,
            html,
            attachments: [
                {
                    filename: "fullLogo.png",
                    path: logoPath,
                    cid: "fullLogo",
                },
            ],
        });

        console.log(`📧 Email sent to ${to}`);
    } catch (err) {
        console.error("❌ Email send failed:", err);
        throw new Error("Email sending failed");
    }
}
