.class public final Landroidx/appcompat/view/menu/db1;
.super Landroidx/appcompat/view/menu/ud1;
.source "SourceFile"


# instance fields
.field public final f:Landroidx/appcompat/view/menu/p4;

.field public final g:Landroidx/appcompat/view/menu/ey;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/v80;Landroidx/appcompat/view/menu/ey;Landroidx/appcompat/view/menu/ay;)V
    .locals 0

    invoke-direct {p0, p1, p3}, Landroidx/appcompat/view/menu/ud1;-><init>(Landroidx/appcompat/view/menu/v80;Landroidx/appcompat/view/menu/ay;)V

    new-instance p1, Landroidx/appcompat/view/menu/p4;

    invoke-direct {p1}, Landroidx/appcompat/view/menu/p4;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/db1;->f:Landroidx/appcompat/view/menu/p4;

    iput-object p2, p0, Landroidx/appcompat/view/menu/db1;->g:Landroidx/appcompat/view/menu/ey;

    iget-object p1, p0, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->a:Landroidx/appcompat/view/menu/v80;

    const-string p2, "ConnectionlessLifecycleHelper"

    invoke-interface {p1, p2, p0}, Landroidx/appcompat/view/menu/v80;->a(Ljava/lang/String;Lcom/google/android/gms/common/api/internal/LifecycleCallback;)V

    return-void
.end method

.method public static u(Landroid/app/Activity;Landroidx/appcompat/view/menu/ey;Landroidx/appcompat/view/menu/q2;)V
    .locals 2

    invoke-static {p0}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->c(Landroid/app/Activity;)Landroidx/appcompat/view/menu/v80;

    move-result-object p0

    const-string v0, "ConnectionlessLifecycleHelper"

    const-class v1, Landroidx/appcompat/view/menu/db1;

    invoke-interface {p0, v0, v1}, Landroidx/appcompat/view/menu/v80;->d(Ljava/lang/String;Ljava/lang/Class;)Lcom/google/android/gms/common/api/internal/LifecycleCallback;

    move-result-object v0

    check-cast v0, Landroidx/appcompat/view/menu/db1;

    if-nez v0, :cond_0

    new-instance v0, Landroidx/appcompat/view/menu/db1;

    invoke-static {}, Landroidx/appcompat/view/menu/ay;->m()Landroidx/appcompat/view/menu/ay;

    move-result-object v1

    invoke-direct {v0, p0, p1, v1}, Landroidx/appcompat/view/menu/db1;-><init>(Landroidx/appcompat/view/menu/v80;Landroidx/appcompat/view/menu/ey;Landroidx/appcompat/view/menu/ay;)V

    :cond_0
    const-string p0, "ApiKey cannot be null"

    invoke-static {p2, p0}, Landroidx/appcompat/view/menu/ij0;->j(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    iget-object p0, v0, Landroidx/appcompat/view/menu/db1;->f:Landroidx/appcompat/view/menu/p4;

    invoke-virtual {p0, p2}, Landroidx/appcompat/view/menu/p4;->add(Ljava/lang/Object;)Z

    invoke-virtual {p1, v0}, Landroidx/appcompat/view/menu/ey;->c(Landroidx/appcompat/view/menu/db1;)V

    return-void
.end method


# virtual methods
.method public final h()V
    .locals 0

    invoke-super {p0}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->h()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/db1;->v()V

    return-void
.end method

.method public final j()V
    .locals 0

    invoke-super {p0}, Landroidx/appcompat/view/menu/ud1;->j()V

    invoke-virtual {p0}, Landroidx/appcompat/view/menu/db1;->v()V

    return-void
.end method

.method public final k()V
    .locals 1

    invoke-super {p0}, Landroidx/appcompat/view/menu/ud1;->k()V

    iget-object v0, p0, Landroidx/appcompat/view/menu/db1;->g:Landroidx/appcompat/view/menu/ey;

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/ey;->d(Landroidx/appcompat/view/menu/db1;)V

    return-void
.end method

.method public final m(Landroidx/appcompat/view/menu/df;I)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/db1;->g:Landroidx/appcompat/view/menu/ey;

    invoke-virtual {v0, p1, p2}, Landroidx/appcompat/view/menu/ey;->F(Landroidx/appcompat/view/menu/df;I)V

    return-void
.end method

.method public final n()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/db1;->g:Landroidx/appcompat/view/menu/ey;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/ey;->a()V

    return-void
.end method

.method public final t()Landroidx/appcompat/view/menu/p4;
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/db1;->f:Landroidx/appcompat/view/menu/p4;

    return-object v0
.end method

.method public final v()V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/db1;->f:Landroidx/appcompat/view/menu/p4;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/p4;->isEmpty()Z

    move-result v0

    if-nez v0, :cond_0

    iget-object v0, p0, Landroidx/appcompat/view/menu/db1;->g:Landroidx/appcompat/view/menu/ey;

    invoke-virtual {v0, p0}, Landroidx/appcompat/view/menu/ey;->c(Landroidx/appcompat/view/menu/db1;)V

    :cond_0
    return-void
.end method
