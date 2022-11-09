/*
 * Copyright (C) 2021 Michael Clarke
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
package com.github.mc1arke.sonarqube.plugin.ce.pullrequest;

import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.ImmutableTriple;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.lang3.tuple.Triple;
import org.sonar.api.issue.Issue;
import org.sonar.api.platform.Server;
import org.sonar.api.rule.Severity;
import org.sonar.api.rules.RuleType;
import org.sonar.ce.task.projectanalysis.scm.Changeset;
import org.sonar.ce.task.projectanalysis.scm.ScmInfoRepository;
import org.sonar.db.alm.setting.AlmSettingDto;
import org.sonar.db.alm.setting.ProjectAlmSettingDto;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.StringReader;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.github.mc1arke.sonarqube.plugin.CommunityBranchPlugin;
import com.github.mc1arke.sonarqube.plugin.ce.pullrequest.AnalysisDetails.ProjectIssueIdentifier;

public abstract class DiscussionAwarePullRequestDecorator<C, P, U, D, N> implements PullRequestBuildStatusDecorator {

    // post this message in case there are non-bot comments on an issue comment and
    // the comment should be resolved
    private static final String RESOLVED_ISSUE_NEEDING_CLOSED_MESSAGE = "This issue no longer exists in SonarQube, but due to other comments being present in this discussion, the discussion is not being being closed automatically. "
            + "Please manually resolve this discussion once the other comments have been reviewed.";

    // enumerate possible status keys that are "open"
    private static final List<String> OPEN_ISSUE_STATUSES = Issue.STATUSES.stream()
            .filter(s -> !Issue.STATUS_CLOSED.equals(s) && !Issue.STATUS_RESOLVED.equals(s))
            .collect(Collectors.toList());

    // link text to view issue in sonarqube
    private static final String VIEW_IN_SONARQUBE_LABEL = "View in SonarQube";
    // pattern for sonarqube link
    private static final Pattern NOTE_MARKDOWN_VIEW_LINK_PATTERN = Pattern
            .compile("^\\[" + VIEW_IN_SONARQUBE_LABEL + "]\\((.*?)\\)$");

    // string hints that a certain comment is indeed a summary
    private static final Set<String> SUMMARY_COMMENT_HINTS = new HashSet<>(Arrays.asList("Analysis Details", "Issue",
            "Bug", "Vulnerabilit", "Code Smell", "Coverage and Duplications", "View in SonarQube"));

    private final Server server;
    private final ScmInfoRepository scmInfoRepository;

    protected DiscussionAwarePullRequestDecorator(Server server, ScmInfoRepository scmInfoRepository) {
        super();
        this.server = server;
        this.scmInfoRepository = scmInfoRepository;
    }

    @Override
    public DecorationResult decorateQualityGateStatus(AnalysisDetails analysis, AlmSettingDto almSettingDto,
            ProjectAlmSettingDto projectAlmSettingDto) {
        // allowed rule types to be annotated as comments
        Set<RuleType> allowedRuleTypes = Arrays.asList(
                analysis.getScannerProperty(CommunityBranchPlugin.PR_ALLOWED_RULE_TYPES).orElse("").trim().split(","))
                .stream().map(s -> {
                    try {
                        return RuleType.valueOf(s);
                    } catch (IllegalArgumentException e) {
                        return null;
                    }
                }).filter(Objects::nonNull).collect(Collectors.toSet());
        // minimum severity to be added as a comment
        String minimumIssueSeverity = analysis.getScannerProperty(CommunityBranchPlugin.PR_MINIMUM_ISSUE_SEVERITY)
                .orElse(Severity.INFO);
        // maximum number of comments to add
        long issueDiscussionThreshold = analysis.getScannerProperty(CommunityBranchPlugin.PR_ISSUE_DISCUSSION_THRESHOLD)
                .map(Long::parseLong).orElse(CommunityBranchPlugin.PR_ISSUE_DISCUSSION_THRESHOLD_UNLIMITED);
        // disable summary
        boolean disableSummary = analysis.getScannerProperty(CommunityBranchPlugin.PR_DISABLE_ANALYSIS_SUMMARY)
                .map(Boolean::parseBoolean).orElse(Boolean.FALSE);
        // delete resolved issues instead of just resolving them
        boolean deleteResolvedIssues = analysis.getScannerProperty(CommunityBranchPlugin.PR_DELETE_RESOLVED_DISCUSSIONS)
                .map(Boolean::parseBoolean).orElse(Boolean.FALSE);
        // reopen resolved issues if issue still present on sonarqube end
        boolean reopenResolvedIssues = analysis.getScannerProperty(CommunityBranchPlugin.PR_REOPEN_RESOLVED_DISCUSSIONS)
                .map(Boolean::parseBoolean).orElse(Boolean.FALSE);
        // delete previous summary comment
        boolean deleteSummaries = analysis.getScannerProperty(CommunityBranchPlugin.PR_DELETE_ANALYSIS_SUMMARY)
                .map(Boolean::parseBoolean).orElse(Boolean.FALSE);
        // disable analysis pipeline
        boolean disableAnalysisPipelineStatus = analysis
                .getScannerProperty(CommunityBranchPlugin.PR_DISABLE_ANALYSIS_PIPELINE_STATUS)
                .map(Boolean::parseBoolean).orElse(Boolean.FALSE);

        // client to talk to the ALM
        C client = createClient(almSettingDto, projectAlmSettingDto);

        // the relevant pull/merge request
        P pullRequest = getPullRequest(client, almSettingDto, projectAlmSettingDto, analysis);

        // user/bot/token used to add comments to the ALM
        U user = getCurrentUser(client);

        // list of all issues on SonarQube
        List<PostAnalysisIssueVisitor.ComponentIssue> sonarqubeIssues = analysis.getPostAnalysisIssueVisitor()
                .getIssues();

        // list of all comments by this bot user on ALM
        List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> existingDiscussions = findSonarqubeComments(client,
                pullRequest, user, analysis);

        // enumerate all "resolved" discussions (i.e all discussions that reference an issue
        // key no longer reported "open" by sonarqube)
        List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> resolvedDiscussions = findResolvedDiscussions(
                existingDiscussions, sonarqubeIssues);

        // enumerate all discussions which should still be active
        List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> currentDiscussions = findCurrentDiscussions(
                existingDiscussions, resolvedDiscussions);

        // get all commits that are relevant for this pull/merge request
        List<String> commitIds = getCommitIdsForPullRequest(client, pullRequest);

        // find all issues for which a comment exists
        List<String> issueIdsWithExistingComments = currentDiscussions.stream().map(Triple::getRight)
                .map(AnalysisDetails.ProjectIssueIdentifier::getIssueKey).collect(Collectors.toList());

        // find all SonarQube issues that have no corresponding comment in the ALM
        List<Pair<PostAnalysisIssueVisitor.ComponentIssue, String>> uncommentedIssues = findIssuesWithoutComments(
                sonarqubeIssues, issueIdsWithExistingComments).stream()
                // load scm paths to each issue
                .map(issue -> loadScmPathsForIssues(issue, analysis))
                // include only those where present
                .filter(Optional::isPresent).map(Optional::get)
                // make sure the reported issue is reported on one of the commits of this
                // pull/merge request
                .filter(issue -> isIssueFromCommitInCurrentRequest(issue.getLeft(), commitIds, scmInfoRepository))
                // also make sure that the issue is not closed
                // (note: we do not want do annotate a "resolved" issue if it's not yet existing as a comment)
                .filter(issue -> isOpen(issue.getLeft()))
                .collect(Collectors.toList());

        Predicate<PostAnalysisIssueVisitor.ComponentIssue> shouldIssueBeCommented = shouldIssueBeCommented(
                minimumIssueSeverity, allowedRuleTypes);

        // check if comments completely disabled
        if (issueDiscussionThreshold != CommunityBranchPlugin.PR_ISSUE_DISCUSSION_THRESHOLD_NONE) {
            Stream<Pair<PostAnalysisIssueVisitor.ComponentIssue, String>> uncommentedIssuesStream = uncommentedIssues
                    .stream();
            // if not all severities included, filter
            uncommentedIssuesStream = uncommentedIssuesStream
                    .filter(issue -> shouldIssueBeCommented.test(issue.getLeft()));
            // sort issues by severity
            if (issueDiscussionThreshold != CommunityBranchPlugin.PR_ISSUE_DISCUSSION_THRESHOLD_UNLIMITED) {
                uncommentedIssuesStream = uncommentedIssuesStream.sorted(Comparator.comparingInt(issue -> -1
                        * CommunityBranchPlugin.PR_SEVERITIES_LIST.indexOf(issue.getLeft().getIssue().severity())));
            }
            // limit by number of allowed comments
            if (issueDiscussionThreshold != CommunityBranchPlugin.PR_ISSUE_DISCUSSION_THRESHOLD_UNLIMITED) {
                uncommentedIssuesStream = uncommentedIssuesStream.limit(issueDiscussionThreshold);
            }
            uncommentedIssuesStream.forEach(issue -> submitCommitNoteForIssue(client, pullRequest, issue.getLeft(),
                    issue.getRight(), analysis));
        }

        // close all "old" discussions (i.e all discussions that reference an issue key
        // no longer reported by sonarqube)
        resolvedDiscussions.stream().forEach(triple -> {
            updateIssueComment(client, pullRequest, triple.getLeft(), triple.getMiddle(), sonarqubeIssues,
                    triple.getRight(), analysis);
            resolveOrPlaceFinalCommentOnDiscussion(client, user, triple.getLeft(), pullRequest,
                    deleteResolvedIssues, deleteSummaries);
        });

        // re-check all existing discussions and either leave open or close/resolve
        currentDiscussions.stream().forEach(triple -> {
            // check if the discussion is currently resolved
            boolean isResolved = isResolved(client, triple.getLeft(), getNotesForDiscussion(client, triple.getLeft()),
                    user);
            // retrieve the linked issue
            Optional<PostAnalysisIssueVisitor.ComponentIssue> issue = sonarqubeIssues.stream()
                    .filter(i -> i.getIssue().key().equals(triple.getRight().getIssueKey())).findFirst();
            // and check if the discussion should actually be resolved
            boolean shouldBeResolved = issue.isPresent() && !shouldIssueBeCommented.test(issue.get());

            if (isResolved && !shouldBeResolved && reopenResolvedIssues) {
                // the issue is resolved although it should be open -> reopen
                updateIssueComment(client, pullRequest, triple.getLeft(), triple.getMiddle(), sonarqubeIssues,
                        triple.getRight(), analysis);
                unresolveDiscussion(client, triple.getLeft(), pullRequest);
            } else if (shouldBeResolved && !isResolved) {
                // the issue should be resolved, but isn't -> resolve/delete
                updateIssueComment(client, pullRequest, triple.getLeft(), triple.getMiddle(), sonarqubeIssues,
                        triple.getRight(), analysis);
                resolveOrPlaceFinalCommentOnDiscussion(client, user, triple.getLeft(), pullRequest,
                        deleteResolvedIssues, deleteSummaries);
            }
        });

        // submit summary only if enabled
        if (!disableSummary) {
            submitSummaryNote(client, pullRequest, analysis);
        }

        // submit pipeline status only if enabled
        if (!disableAnalysisPipelineStatus) {
            submitPipelineStatus(client, pullRequest, analysis, server.getPublicRootUrl());
        }

        DecorationResult.Builder builder = DecorationResult.builder();
        createFrontEndUrl(pullRequest, analysis).ifPresent(builder::withPullRequestUrl);
        return builder.build();
    }

    protected abstract C createClient(AlmSettingDto almSettingDto, ProjectAlmSettingDto projectAlmSettingDto);

    protected abstract Optional<String> createFrontEndUrl(P pullRequest, AnalysisDetails analysisDetails);

    protected abstract P getPullRequest(C client, AlmSettingDto almSettingDto,
            ProjectAlmSettingDto projectAlmSettingDto, AnalysisDetails analysis);

    protected abstract U getCurrentUser(C client);

    protected abstract List<String> getCommitIdsForPullRequest(C client, P pullRequest);

    protected abstract void submitPipelineStatus(C client, P pullRequest, AnalysisDetails analysis,
            String sonarqubeRootUrl);

    protected abstract void submitCommitNoteForIssue(C client, P pullRequest,
            PostAnalysisIssueVisitor.ComponentIssue issue, String filePath, AnalysisDetails analysis);

    protected abstract void updateCommitNoteForIssue(C client, P pullRequest, D discussion, N note,
            PostAnalysisIssueVisitor.ComponentIssue issue, AnalysisDetails analysis);

    protected abstract String getNoteContent(C client, N note);

    protected abstract List<N> getNotesForDiscussion(C client, D discussion);

    protected abstract boolean isClosed(D discussion, List<N> notesInDiscussion);

    protected abstract boolean isUserNote(N note);

    protected abstract void addNoteToDiscussion(C client, D discussion, P pullRequest, String note);

    protected abstract void updateNoteInDiscussion(C client, D discussion, N note, P pullRequest,
            String newNoteContent);

    protected abstract void deleteDiscussionNote(C client, D discussion, P pullRequest, N note);

    protected abstract void resolveDiscussion(C client, D discussion, P pullRequest);

    protected abstract void unresolveDiscussion(C client, D discussion, P pullRequest);

    protected abstract void submitSummaryNote(C client, P pullRequest, AnalysisDetails analysis);

    protected abstract List<D> getDiscussions(C client, P pullRequest);

    protected abstract boolean isNoteFromCurrentUser(N note, U user);

    private static List<PostAnalysisIssueVisitor.ComponentIssue> findIssuesWithoutComments(
            List<PostAnalysisIssueVisitor.ComponentIssue> openSonarqubeIssues,
            List<String> openGitlabIssueIdentifiers) {
        return openSonarqubeIssues.stream()
                .filter(issue -> !openGitlabIssueIdentifiers.contains(issue.getIssue().key()))
                .filter(issue -> issue.getIssue().getLine() != null).collect(Collectors.toList());
    }

    private static Optional<Pair<PostAnalysisIssueVisitor.ComponentIssue, String>> loadScmPathsForIssues(
            PostAnalysisIssueVisitor.ComponentIssue componentIssue, AnalysisDetails analysis) {
        return Optional.of(componentIssue).map(issue -> ImmutablePair.of(issue, analysis.getSCMPathForIssue(issue)))
                .filter(pair -> pair.getRight().isPresent())
                .map(pair -> ImmutablePair.of(pair.getLeft(), pair.getRight().get()));
    }

    private static boolean isIssueFromCommitInCurrentRequest(PostAnalysisIssueVisitor.ComponentIssue componentIssue,
            List<String> commitIds, ScmInfoRepository scmInfoRepository) {
        return Optional.of(componentIssue)
                .map(issue -> ImmutablePair.of(issue.getIssue(), scmInfoRepository.getScmInfo(issue.getComponent())))
                .filter(issuePair -> issuePair.getRight().isPresent())
                .map(issuePair -> ImmutablePair.of(issuePair.getLeft(), issuePair.getRight().get()))
                .filter(issuePair -> null != issuePair.getLeft().getLine())
                .filter(issuePair -> issuePair.getRight().hasChangesetForLine(issuePair.getLeft().getLine()))
                .map(issuePair -> issuePair.getRight().getChangesetForLine(issuePair.getLeft().getLine()))
                .map(Changeset::getRevision).filter(commitIds::contains).isPresent();
    }

    /**
     * Find all discussions/comments in the current pull/merge request which contain
     * at least one comment by the sonarqube user
     * 
     * @param client          the ALM client to fetch the discussions from
     * @param pullRequest     the pull request which is analyzed
     * @param currentUser     the user which adds the comments
     * @param analysisDetails
     * @return a list of all discussions and comments by the current user (and
     *         project)
     */
    private List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> findSonarqubeComments(C client, P pullRequest,
            U currentUser, AnalysisDetails analysisDetails) {
        // stream all discussions of the current merge/pull request
        return getDiscussions(client, pullRequest).stream()
                // map each discussion to a triple of
                // <discussion, note-of-current-user, issue-details>
                .map(discussion -> {
                    // get all notes for the current discussion
                    List<N> commentsForDiscussion = getNotesForDiscussion(client, discussion);
                    // use the first note in the discussion which is from the current user
                    return commentsForDiscussion.stream().findFirst()
                            .filter(note -> isNoteFromCurrentUser(note, currentUser)).map(note -> ImmutableTriple
                                    .of(discussion, note, parseIssueDetails(client, note, analysisDetails)));
                })
                // only include discussions which include a note from our user
                .filter(Optional::isPresent)
                // get these
                .map(Optional::get)
                // only include dicussions where
                // a) issue identifier is present and
                // b) is from current project
                .filter(comment -> isCommentFromCurrentProject(comment.getRight(),
                        analysisDetails.getAnalysisProjectKey()))
                .map(t -> ImmutableTriple.of(t.getLeft(), t.getMiddle(), t.getRight().get()))
                // and return as map
                .collect(Collectors.toList());
    }

    /**
     * Find all discussions that reference a SonarQube issue that is no longer "open"
     * 
     * @param sonarqubeComments the list of existing comments by SonarQube
     * @param issues            the current set of SonarQube issues
     * @return a filtered list of comments that reference a no longer existing issue
     */
    private List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> findResolvedDiscussions(
            List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> sonarqubeComments,
            List<PostAnalysisIssueVisitor.ComponentIssue> issues) {

        // collect the set of all known "open" issues
        Set<String> openIssueKeys = issues.stream().filter(issue -> isOpen(issue)).map(issue -> issue.getIssue().key())
                .collect(Collectors.toSet());

        return sonarqubeComments.stream()
                // return comments which are _not_ in the set of open issues
                .filter(t -> !openIssueKeys.contains(t.getRight().getIssueKey()))
                // return as list
                .collect(Collectors.toList());
    }

    /**
     * Return all existing comments which refer to an existing issue (i.e. filter
     * allComments by oldComments).
     * 
     * @param allComments all existing comments
     * @param oldComments outdated comments
     * @return the not outdated comments
     */
    private List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> findCurrentDiscussions(
            List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> allComments,
            List<Triple<D, N, AnalysisDetails.ProjectIssueIdentifier>> oldComments) {
        Set<String> oldKeys = oldComments.stream().map(Triple::getRight)
                .map(AnalysisDetails.ProjectIssueIdentifier::getIssueKey).collect(Collectors.toSet());

        return allComments.stream().filter(t -> !oldKeys.contains(t.getRight().getIssueKey()))
                .collect(Collectors.toList());
    }

    private boolean isResolved(C client, D discussion, List<N> notesInDiscussion, U currentUser) {
        return isClosed(discussion, notesInDiscussion)
                || notesInDiscussion.stream().filter(message -> isNoteFromCurrentUser(message, currentUser)).anyMatch(
                        message -> RESOLVED_ISSUE_NEEDING_CLOSED_MESSAGE.equals(getNoteContent(client, message)));
    }

    private boolean isSummaryNote(C client, N note) {
        String noteContent = getNoteContent(client, note);
        return SUMMARY_COMMENT_HINTS.stream().allMatch(hint -> noteContent.contains(hint));
    }

    private void updateIssueComment(C client, P pullRequest, D discussion, N note,
            List<PostAnalysisIssueVisitor.ComponentIssue> sonarqubeIssues, ProjectIssueIdentifier identifier,
            AnalysisDetails analysis) {
        // this is not ideal, this should be a map
        Optional<PostAnalysisIssueVisitor.ComponentIssue> issue = sonarqubeIssues.stream()
                .filter(i -> i.getIssue().key().equals(identifier.getIssueKey())).findFirst();
        if (issue.isPresent()) {
            updateCommitNoteForIssue(client, pullRequest, discussion, note, issue.get(), analysis);
        }
    }

    private void resolveOrPlaceFinalCommentOnDiscussion(C client, U currentUser, D discussion, P pullRequest,
            boolean deleteResolvedIssues, boolean deleteSummary) {
        List<N> discussionNotes = getNotesForDiscussion(client, discussion);
        boolean isAlreadyResolved = isResolved(client, discussion, discussionNotes, currentUser);
        // check if discussion contains a summary
        boolean isSummary = discussionNotes.stream().anyMatch(note -> isSummaryNote(client, note));
        if (discussionNotes.stream().filter(this::isUserNote)
                .anyMatch(note -> !isNoteFromCurrentUser(note, currentUser))) {
            if (!isAlreadyResolved) {
                // add note to end of discussion thread that this thread should be closed
                addNoteToDiscussion(client, discussion, pullRequest, RESOLVED_ISSUE_NEEDING_CLOSED_MESSAGE);
            }
        } else {
            if (deleteResolvedIssues && !isSummary || deleteSummary && isSummary) {
                discussionNotes.stream().filter(note -> isNoteFromCurrentUser(note, currentUser))
                        .forEach(note -> deleteDiscussionNote(client, discussion, pullRequest, note));
            } else {
                if (!isAlreadyResolved) {
                    resolveDiscussion(client, discussion, pullRequest);
                }
            }
        }
    }

    protected Optional<AnalysisDetails.ProjectIssueIdentifier> parseIssueDetails(C client, N note,
            AnalysisDetails analysisDetails) {
        return parseIssueDetails(client, note, analysisDetails, VIEW_IN_SONARQUBE_LABEL,
                NOTE_MARKDOWN_VIEW_LINK_PATTERN);
    }

    protected Optional<AnalysisDetails.ProjectIssueIdentifier> parseIssueDetails(C client, N note,
            AnalysisDetails analysisDetails, String label, Pattern pattern) {
        try (BufferedReader reader = new BufferedReader(new StringReader(getNoteContent(client, note)))) {
            return reader.lines().filter(line -> line.contains(label))
                    .map(line -> parseIssueLineDetails(line, analysisDetails, pattern)).filter(Optional::isPresent)
                    .map(Optional::get).findFirst();
        } catch (IOException ex) {
            throw new IllegalStateException("Could not parse details from note", ex);
        }
    }

    private static Optional<AnalysisDetails.ProjectIssueIdentifier> parseIssueLineDetails(String noteLine,
            AnalysisDetails analysisDetails, Pattern pattern) {
        Matcher identifierMatcher = pattern.matcher(noteLine);

        if (identifierMatcher.matches()) {
            return analysisDetails.parseIssueIdFromUrl(identifierMatcher.group(1));
        } else {
            return Optional.empty();
        }
    }

    private static boolean isCommentFromCurrentProject(
            Optional<AnalysisDetails.ProjectIssueIdentifier> optionalProjectIssueIdentifier, String projectId) {
        return optionalProjectIssueIdentifier
                .filter(projectIssueIdentifier -> projectId.equals(projectIssueIdentifier.getProjectKey())).isPresent();
    }

    private static Predicate<PostAnalysisIssueVisitor.ComponentIssue> shouldIssueBeCommented(
            String minimumIssueSeverity, Set<RuleType> allowedRuleTypes) {
        Predicate<PostAnalysisIssueVisitor.ComponentIssue> predicate = issue -> true;
        // if not all severities included, filter
        if (!minimumIssueSeverity.equals(Severity.INFO)) {
            int minimumSeverityIndex = CommunityBranchPlugin.PR_SEVERITIES_LIST.indexOf(minimumIssueSeverity);
            Predicate<PostAnalysisIssueVisitor.ComponentIssue> filterForIssueSeverity = issue -> {
                String issueSeverity = issue.getIssue().severity();
                int issueSeverityIndex = CommunityBranchPlugin.PR_SEVERITIES_LIST.indexOf(issueSeverity);
                return issueSeverityIndex >= minimumSeverityIndex;
            };
            predicate = predicate.and(filterForIssueSeverity);
        }
        // filter by allowed rule types (empty: all are allowed)
        if (!allowedRuleTypes.isEmpty()) {
            Predicate<PostAnalysisIssueVisitor.ComponentIssue> filterForRuleType = issue -> allowedRuleTypes
                    .contains(issue.getIssue().type());
            predicate = predicate.and(filterForRuleType);
        }
        return predicate;
    }

    private static boolean isOpen(PostAnalysisIssueVisitor.ComponentIssue issue) {
        return OPEN_ISSUE_STATUSES.contains(issue.getIssue().getStatus());
    }
}
