.class public Landroidx/appcompat/view/menu/fd$h;
.super Ljava/util/AbstractCollection;
.source "SourceFile"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Landroidx/appcompat/view/menu/fd;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x1
    name = "h"
.end annotation


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/fd;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/fd;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/fd$h;->m:Landroidx/appcompat/view/menu/fd;

    invoke-direct {p0}, Ljava/util/AbstractCollection;-><init>()V

    return-void
.end method


# virtual methods
.method public clear()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/fd$h;->m:Landroidx/appcompat/view/menu/fd;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/fd;->clear()V

    return-void
.end method

.method public iterator()Ljava/util/Iterator;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/fd$h;->m:Landroidx/appcompat/view/menu/fd;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/fd;->X()Ljava/util/Iterator;

    move-result-object v0

    return-object v0
.end method

.method public size()I
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/fd$h;->m:Landroidx/appcompat/view/menu/fd;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/fd;->size()I

    move-result v0

    return v0
.end method
