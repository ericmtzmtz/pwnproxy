export interface Comment {
  id: number;
  flow_id: number;
  body: string;
  kind: "note" | "flag" | "todo";
  resolved: boolean;
  author: string | null;
  created_at: string | null;
  updated_at: string | null;
}

export interface CommentCreatePayload {
  body: string;
  kind?: "note" | "flag" | "todo";
  resolved?: boolean;
  author?: string | null;
}

export interface CommentUpdatePayload {
  body?: string;
  kind?: "note" | "flag" | "todo";
  resolved?: boolean;
}
