import { z } from "zod";

export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export type Severity = z.infer<typeof SeveritySchema>;

export const FindingSourceSchema = z.enum(["llm", "semgrep", "osv"]);
export type FindingSource = z.infer<typeof FindingSourceSchema>;

export const OwaspCategorySchema = z.enum([
  "A01",
  "A02",
  "A03",
  "A04",
  "A05",
  "A06",
  "A07",
  "A08",
  "A09",
  "A10",
]);
export type OwaspCategory = z.infer<typeof OwaspCategorySchema>;

export const FindingSchema = z.object({
  file: z.string(),
  line: z.number().int().positive(),
  owaspCategory: OwaspCategorySchema,
  cwe: z.string().optional(),
  severity: SeveritySchema,
  message: z.string(),
  suggestedFix: z.string(),
  source: FindingSourceSchema,
  package: z.string().optional(),
  version: z.string().optional(),
  cveId: z.string().optional(),
  fixedVersion: z.string().optional(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ReviewResultSchema = z.object({
  summary: z.string(),
  findings: z.array(FindingSchema),
  degradedLayers: z.array(z.string()).default([]),
  metadata: z
    .object({
      model: z.string().optional(),
      latencyMs: z.number().optional(),
      semgrepCount: z.number().optional(),
      osvCount: z.number().optional(),
      triageFiles: z.array(z.string()).optional(),
      toolsUsed: z.array(z.string()).optional(),
      stepCount: z.number().optional(),
      semgrepEnabled: z.boolean().optional(),
      autofixCommitSha: z.string().optional(),
      autofixPackages: z.array(z.string()).optional(),
    })
    .optional(),
});
export type ReviewResult = z.infer<typeof ReviewResultSchema>;

export const SemgrepFindingSchema = z.object({
  check_id: z.string(),
  path: z.string(),
  start: z.object({ line: z.number() }),
  extra: z.object({
    message: z.string(),
    severity: z.string().optional(),
    metadata: z
      .object({
        cwe: z.union([z.string(), z.array(z.string())]).optional(),
        owasp: z.union([z.string(), z.array(z.string())]).optional(),
      })
      .optional(),
  }),
});
export type SemgrepFinding = z.infer<typeof SemgrepFindingSchema>;

export interface PullRequestContext {
  owner: string;
  repo: string;
  pullNumber: number;
  headSha: string;
  headRef: string;
  headOwner: string;
  headRepo: string;
  baseSha: string;
  installationId: number;
  deliveryId: string;
}

export interface DiffFile {
  filename: string;
  status: string;
  patch?: string;
  additions: number;
  deletions: number;
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function sortFindingsBySeverity(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity],
  );
}
