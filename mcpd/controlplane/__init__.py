"""Declarative control plane artifacts for mcpd."""

from .loader import Artifact, ArtifactMetadata, ArtifactStore, load_artifact_store

__all__ = [
    "Artifact",
    "ArtifactMetadata",
    "ArtifactStore",
    "load_artifact_store",
]
