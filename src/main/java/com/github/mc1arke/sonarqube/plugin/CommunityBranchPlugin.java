/*
 * Copyright (C) 2020-2021 Michael Clarke
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
package com.github.mc1arke.sonarqube.plugin;

import java.util.List;

import com.github.mc1arke.sonarqube.plugin.ce.CommunityReportAnalysisComponentProvider;
import com.github.mc1arke.sonarqube.plugin.scanner.CommunityBranchConfigurationLoader;
import com.github.mc1arke.sonarqube.plugin.scanner.CommunityBranchParamsValidator;
import com.github.mc1arke.sonarqube.plugin.scanner.CommunityProjectBranchesLoader;
import com.github.mc1arke.sonarqube.plugin.scanner.CommunityProjectPullRequestsLoader;
import com.github.mc1arke.sonarqube.plugin.scanner.ScannerPullRequestPropertySensor;
import com.github.mc1arke.sonarqube.plugin.server.CommunityBranchFeatureExtension;
import com.github.mc1arke.sonarqube.plugin.server.CommunityBranchSupportDelegate;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.CreateBitbucketCloudAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.DeleteBindingAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.SetAzureBindingAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.SetBitbucketBindingAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.SetBitbucketCloudBindingAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.SetGithubBindingAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.SetGitlabBindingAction;
import com.github.mc1arke.sonarqube.plugin.server.pullrequest.ws.action.UpdateBitbucketCloudAction;
import org.sonar.api.CoreProperties;
import org.sonar.api.Plugin;
import org.sonar.api.PropertyType;
import org.sonar.api.SonarQubeSide;
import org.sonar.api.config.PropertyDefinition;
import org.sonar.api.resources.Qualifiers;
import org.sonar.api.rule.Severity;
import org.sonar.api.rules.RuleType;
import org.sonar.core.config.PurgeConstants;
import org.sonar.core.extension.CoreExtension;

/**
 * @author Michael Clarke
 */
public class CommunityBranchPlugin implements Plugin, CoreExtension {

    // name of configuration items in Sonarqube UI
    public static final String SUBCATEGORY_INDIVIDUAL_DISCUSSIONS = "Individual Discussion Threads";
    public static final String SUBCATEGORY_SUMMARY = "Summary Analysis";
    public static final String SUBCATEGORY_PIPELINE = "Pipeline";

    public static final String IMAGE_URL_BASE = "com.github.mc1arke.sonarqube.plugin.branch.image-url-base";

    // only list certain rule types as comments
    public static final String PR_ALLOWED_RULE_TYPES =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.filter.ruleType";
    // minimum issue severity for an issue to trigger a comment
    public static final String PR_MINIMUM_ISSUE_SEVERITY =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.filter.minimumIssueSeverity";
    // maximum number of issues to add
    public static final String PR_ISSUE_DISCUSSION_THRESHOLD =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.issueDiscussionThreshold";

    // disable analysis summary comment
    public static final String PR_DISABLE_ANALYSIS_SUMMARY =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.summary.disable";
    // delete analysis summary discussions instead of "just" resolving them
    public static final String PR_DELETE_ANALYSIS_SUMMARY =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.summary.delete";

    // delete resolved discussions
    public static final String PR_DELETE_RESOLVED_DISCUSSIONS =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.discussions.delete-resolved";

    // re-open resolved discussions
    public static final String PR_REOPEN_RESOLVED_DISCUSSIONS =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.discussions.reopen-resolved";

    // disable analysis pipeline status
    public static final String PR_DISABLE_ANALYSIS_PIPELINE_STATUS =
            "com.github.mc1arke.sonarqube.plugin.branch.pullrequest.pipelinestatus.disable";

    // list of available rule types
    public static final List<String> PR_RULE_TYPES_LIST = List.of(
            RuleType.BUG.name(), RuleType.VULNERABILITY.name(), RuleType.SECURITY_HOTSPOT.name(), RuleType.CODE_SMELL.name());
    // (sorted) list of available severities
    public static final List<String> PR_SEVERITIES_LIST = List.of(
            Severity.INFO, Severity.MINOR, Severity.MAJOR, Severity.CRITICAL, Severity.BLOCKER);
    // threshold value for unlimited comments
    public static final long PR_ISSUE_DISCUSSION_THRESHOLD_UNLIMITED = -1L;
    // threshold value for no comments
    public static final long PR_ISSUE_DISCUSSION_THRESHOLD_NONE = 0L;

    @Override
    public String getName() {
        return "Community Branch Plugin";
    }

    @Override
    public void load(CoreExtension.Context context) {
        if (SonarQubeSide.COMPUTE_ENGINE == context.getRuntime().getSonarQubeSide()) {
            context.addExtensions(CommunityReportAnalysisComponentProvider.class);
        } else if (SonarQubeSide.SERVER == context.getRuntime().getSonarQubeSide()) {
            context.addExtensions(CommunityBranchFeatureExtension.class, CommunityBranchSupportDelegate.class,
                                  DeleteBindingAction.class,
                                  SetGithubBindingAction.class,
                                  SetAzureBindingAction.class,
                                  SetBitbucketBindingAction.class,
                                  SetBitbucketCloudBindingAction.class,
                                  SetGitlabBindingAction.class, CreateBitbucketCloudAction.class, UpdateBitbucketCloudAction.class,


                /* org.sonar.db.purge.PurgeConfiguration uses the value for the this property if it's configured, so it only
                needs to be specified here, but doesn't need any additional classes to perform the relevant purge/cleanup
                */
                                  PropertyDefinition
                                          .builder(PurgeConstants.DAYS_BEFORE_DELETING_INACTIVE_BRANCHES_AND_PRS)
                                          .name("Number of days before purging inactive branches and pull requests")
                                          .description(
                                                  "Branches and pull requests are permanently deleted when there has been no analysis for the configured number of days.")
                                          .category(CoreProperties.CATEGORY_HOUSEKEEPING)
                                          .subCategory(CoreProperties.SUBCATEGORY_BRANCHES_AND_PULL_REQUESTS).defaultValue("30")
                                          .type(PropertyType.INTEGER)
                                          .index(1)
                                          .build()
                                  ,

                                  PropertyDefinition
                                          .builder(PurgeConstants.BRANCHES_TO_KEEP_WHEN_INACTIVE)
                                          .name("Branches to keep when inactive")
                                          .description("By default, branches and pull requests are automatically deleted when inactive. This setting allows you "
                                                + "to protect branches (but not pull requests) from this deletion. When a branch is created with a name that "
                                                + "matches any of the regular expressions on the list of values of this setting, the branch will not be deleted "
                                                + "automatically even when it becomes inactive. Example:"
                                                + "<ul><li>develop</li><li>release-.*</li></ul>")
                                          .category(CoreProperties.CATEGORY_HOUSEKEEPING)
                                          .subCategory(CoreProperties.SUBCATEGORY_BRANCHES_AND_PULL_REQUESTS)
                                          .multiValues(true)
                                          .defaultValue("master,develop,trunk")
                                          .onQualifiers(Qualifiers.PROJECT)
                                          .index(2)
                                          .build()

                                 );

        }

        if (SonarQubeSide.COMPUTE_ENGINE == context.getRuntime().getSonarQubeSide() ||
            SonarQubeSide.SERVER == context.getRuntime().getSonarQubeSide()) {
            context.addExtensions(PropertyDefinition.builder(IMAGE_URL_BASE)
                                          .category(CoreProperties.CATEGORY_GENERAL)
                                          .subCategory(CoreProperties.SUBCATEGORY_GENERAL)
                                          .onQualifiers(Qualifiers.APP)
                                          .name("Images base URL")
                                          .description("Base URL used to load the images for the PR comments (please use this only if images are not displayed properly).")
                                          .type(PropertyType.STRING)
                                          .build());

            int index = 1;
            // only add issue comments for these rule types
            context.addExtensions(PropertyDefinition.builder(PR_ALLOWED_RULE_TYPES)
                    .category(getName())
                    .subCategory(SUBCATEGORY_INDIVIDUAL_DISCUSSIONS)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Rule types to add comments for")
                    .description("Rule types for issue discussion thread creation (empty: all allowed) (Gitlab and Azure DevOps only).")
                    .type(PropertyType.SINGLE_SELECT_LIST)
                    .options(PR_RULE_TYPES_LIST)
                    .multiValues(true)
                    .index(index++)
                    .build());

            // only add issue comments if issue has a minimum severity
            context.addExtensions(PropertyDefinition.builder(PR_MINIMUM_ISSUE_SEVERITY)
                    .category(getName())
                    .subCategory(SUBCATEGORY_INDIVIDUAL_DISCUSSIONS)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Minimum issue severity for comment")
                    .description("Minimum level of severity required for issue discussion thread creation (Gitlab and Azure DevOps only).")
                    .type(PropertyType.SINGLE_SELECT_LIST)
                    .options(PR_SEVERITIES_LIST)
                    .defaultValue(Severity.INFO)
                    .index(index++)
                    .build());

            // do not add more than this number of issues to the analysis
            context.addExtensions(PropertyDefinition.builder(PR_ISSUE_DISCUSSION_THRESHOLD)
                    .category(getName())
                    .subCategory(SUBCATEGORY_INDIVIDUAL_DISCUSSIONS)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Maximum number of issue comments")
                    .description("Maximum number of issues for which discussion threads will be created ("
                            + PR_ISSUE_DISCUSSION_THRESHOLD_UNLIMITED + ": unlimited, "
                            + PR_ISSUE_DISCUSSION_THRESHOLD_NONE + ": none) (Gitlab and Azure DevOps only).")
                    .type(PropertyType.INTEGER)
                    .defaultValue(String.valueOf(PR_ISSUE_DISCUSSION_THRESHOLD_UNLIMITED))
                    .index(index++)
                    .build());

            // delete all resolved discussions (unless there's other user's comments on the same thread)
            context.addExtensions(PropertyDefinition.builder(PR_DELETE_RESOLVED_DISCUSSIONS)
                    .category(getName())
                    .subCategory(SUBCATEGORY_INDIVIDUAL_DISCUSSIONS)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Delete resolved issues")
                    .description("Delete issue discussion threads instead of resolving them (Gitlab only).")
                    .type(PropertyType.BOOLEAN)
                    .defaultValue(String.valueOf(false))
                    .index(index++)
                    .build());

            // un-resolve (re-open) resolved issues that reference a still-pending issue
            context.addExtensions(PropertyDefinition.builder(PR_REOPEN_RESOLVED_DISCUSSIONS)
                    .category(getName())
                    .subCategory(SUBCATEGORY_INDIVIDUAL_DISCUSSIONS)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Reopen resolved issues")
                    .description("Reopen resolved issues if issue is still pending (Gitlab only).")
                    .type(PropertyType.BOOLEAN)
                    .defaultValue(String.valueOf(false))
                    .index(index++)
                    .build());

            // disable posting analysis summary
            context.addExtensions(PropertyDefinition.builder(PR_DISABLE_ANALYSIS_SUMMARY)
                    .category(getName())
                    .subCategory(SUBCATEGORY_SUMMARY)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Disable analysis summary")
                    .description("Disable analysis summary discussion thread creation (Gitlab and Azure DevOps only).")
                    .type(PropertyType.BOOLEAN)
                    .defaultValue(String.valueOf(false))
                    .index(index++)
                    .build());

            // delete old summaries instead of resolving
            context.addExtensions(PropertyDefinition.builder(PR_DELETE_ANALYSIS_SUMMARY)
                    .category(getName())
                    .subCategory(SUBCATEGORY_SUMMARY)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Delete summaries")
                    .description("Delete summary discussion threads instead of resolving them (Gitlab only).")
                    .type(PropertyType.BOOLEAN)
                    .defaultValue(String.valueOf(false))
                    .index(index++)
                    .build());

            // do not post pipeline status
            context.addExtensions(PropertyDefinition.builder(PR_DISABLE_ANALYSIS_PIPELINE_STATUS)
                    .category(getName())
                    .subCategory(SUBCATEGORY_PIPELINE)
                    .onQualifiers(Qualifiers.PROJECT)
                    .name("Disable analysis pipeline status")
                    .description("Disable analysis pipeline status creation (Gitlab and Azure DevOps only).")
                    .type(PropertyType.BOOLEAN)
                    .defaultValue(String.valueOf(false))
                    .index(index++)
                    .build());
        }
    }

    @Override
    public void define(Plugin.Context context) {
        if (SonarQubeSide.SCANNER == context.getRuntime().getSonarQubeSide()) {
            context.addExtensions(CommunityProjectBranchesLoader.class, CommunityProjectPullRequestsLoader.class,
                                  CommunityBranchConfigurationLoader.class, CommunityBranchParamsValidator.class,
                                  ScannerPullRequestPropertySensor.class);
        }
    }
}
