export function nativeServiceOf(schemaId: unknown): 'chatgpt' | 'claude' | 'grok' | null;
export function nativePlanValues(reference: {schemaId: string; version: number}): string[];
export function nativePlanLabel(reference: {schemaId: string; version: number}, plan: unknown): string | null;
