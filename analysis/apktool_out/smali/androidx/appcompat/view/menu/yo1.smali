.class public abstract Landroidx/appcompat/view/menu/yo1;
.super Landroidx/appcompat/view/menu/dr1;
.source "SourceFile"


# instance fields
.field public b:Z


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/yw1;)V
    .locals 0

    invoke-direct {p0, p1}, Landroidx/appcompat/view/menu/dr1;-><init>(Landroidx/appcompat/view/menu/yw1;)V

    iget-object p1, p0, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->n()V

    return-void
.end method


# virtual methods
.method public abstract A()Z
.end method

.method public final v()V
    .locals 2

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yo1;->z()Z

    move-result v0

    if-eqz v0, :cond_0

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Not initialized"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final w()V
    .locals 2

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/yo1;->b:Z

    if-nez v0, :cond_1

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yo1;->A()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->R()V

    const/4 v0, 0x1

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/yo1;->b:Z

    :cond_0
    return-void

    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Can\'t initialize twice"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public final x()V
    .locals 2

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/yo1;->b:Z

    if-nez v0, :cond_0

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/yo1;->y()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/bz1;->a:Landroidx/appcompat/view/menu/yw1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/yw1;->R()V

    const/4 v0, 0x1

    iput-boolean v0, p0, Landroidx/appcompat/view/menu/yo1;->b:Z

    return-void

    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Can\'t initialize twice"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method

.method public y()V
    .locals 0

    return-void
.end method

.method public final z()Z
    .locals 1

    iget-boolean v0, p0, Landroidx/appcompat/view/menu/yo1;->b:Z

    if-eqz v0, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
