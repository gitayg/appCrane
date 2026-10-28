-- deployments.failure_reason: the one-line reason a deploy failed, the text of
-- its log's "DEPLOY FAILED:" line. Before this the reason lived only inside the
-- full log, so a caller polling a deployment saw status 'failed' and nothing
-- else. NULL for every deploy that did not fail and for failures before this.
ALTER TABLE deployments ADD COLUMN failure_reason TEXT;
