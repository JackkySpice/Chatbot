.class public final Landroidx/appcompat/view/menu/rd1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final m:Landroidx/appcompat/view/menu/md1;

.field public final synthetic n:Landroidx/appcompat/view/menu/ud1;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/ud1;Landroidx/appcompat/view/menu/md1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Landroidx/appcompat/view/menu/rd1;->m:Landroidx/appcompat/view/menu/md1;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 8

    iget-object v0, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-boolean v0, v0, Landroidx/appcompat/view/menu/ud1;->b:Z

    if-nez v0, :cond_0

    return-void

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/rd1;->m:Landroidx/appcompat/view/menu/md1;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/md1;->b()Landroidx/appcompat/view/menu/df;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/df;->k()Z

    move-result v1

    if-eqz v1, :cond_1

    iget-object v1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v2, v1, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->a:Landroidx/appcompat/view/menu/v80;

    invoke-virtual {v1}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->b()Landroid/app/Activity;

    move-result-object v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/df;->i()Landroid/app/PendingIntent;

    move-result-object v0

    invoke-static {v0}, Landroidx/appcompat/view/menu/ij0;->i(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Landroid/app/PendingIntent;

    iget-object v3, p0, Landroidx/appcompat/view/menu/rd1;->m:Landroidx/appcompat/view/menu/md1;

    invoke-virtual {v3}, Landroidx/appcompat/view/menu/md1;->a()I

    move-result v3

    const/4 v4, 0x0

    invoke-static {v1, v0, v3, v4}, Lcom/google/android/gms/common/api/GoogleApiActivity;->a(Landroid/content/Context;Landroid/app/PendingIntent;IZ)Landroid/content/Intent;

    move-result-object v0

    const/4 v1, 0x1

    invoke-interface {v2, v0, v1}, Landroidx/appcompat/view/menu/v80;->startActivityForResult(Landroid/content/Intent;I)V

    return-void

    :cond_1
    iget-object v1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v2, v1, Landroidx/appcompat/view/menu/ud1;->e:Landroidx/appcompat/view/menu/ay;

    invoke-virtual {v1}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->b()Landroid/app/Activity;

    move-result-object v1

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/df;->d()I

    move-result v3

    const/4 v4, 0x0

    invoke-virtual {v2, v1, v3, v4}, Landroidx/appcompat/view/menu/ay;->b(Landroid/content/Context;ILjava/lang/String;)Landroid/content/Intent;

    move-result-object v1

    if-eqz v1, :cond_2

    iget-object v1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v2, v1, Landroidx/appcompat/view/menu/ud1;->e:Landroidx/appcompat/view/menu/ay;

    invoke-virtual {v1}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->b()Landroid/app/Activity;

    move-result-object v3

    iget-object v1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v4, v1, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->a:Landroidx/appcompat/view/menu/v80;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/df;->d()I

    move-result v5

    const/4 v6, 0x2

    iget-object v7, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    invoke-virtual/range {v2 .. v7}, Landroidx/appcompat/view/menu/ay;->v(Landroid/app/Activity;Landroidx/appcompat/view/menu/v80;IILandroid/content/DialogInterface$OnCancelListener;)Z

    return-void

    :cond_2
    invoke-virtual {v0}, Landroidx/appcompat/view/menu/df;->d()I

    move-result v1

    const/16 v2, 0x12

    if-ne v1, v2, :cond_3

    iget-object v0, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v1, v0, Landroidx/appcompat/view/menu/ud1;->e:Landroidx/appcompat/view/menu/ay;

    invoke-virtual {v0}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->b()Landroid/app/Activity;

    move-result-object v0

    iget-object v2, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    invoke-virtual {v1, v0, v2}, Landroidx/appcompat/view/menu/ay;->q(Landroid/app/Activity;Landroid/content/DialogInterface$OnCancelListener;)Landroid/app/Dialog;

    move-result-object v0

    iget-object v1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v2, v1, Landroidx/appcompat/view/menu/ud1;->e:Landroidx/appcompat/view/menu/ay;

    invoke-virtual {v1}, Lcom/google/android/gms/common/api/internal/LifecycleCallback;->b()Landroid/app/Activity;

    move-result-object v1

    invoke-virtual {v1}, Landroid/content/Context;->getApplicationContext()Landroid/content/Context;

    move-result-object v1

    new-instance v3, Landroidx/appcompat/view/menu/pd1;

    invoke-direct {v3, p0, v0}, Landroidx/appcompat/view/menu/pd1;-><init>(Landroidx/appcompat/view/menu/rd1;Landroid/app/Dialog;)V

    invoke-virtual {v2, v1, v3}, Landroidx/appcompat/view/menu/ay;->r(Landroid/content/Context;Landroidx/appcompat/view/menu/vb1;)Landroidx/appcompat/view/menu/wb1;

    return-void

    :cond_3
    iget-object v1, p0, Landroidx/appcompat/view/menu/rd1;->n:Landroidx/appcompat/view/menu/ud1;

    iget-object v2, p0, Landroidx/appcompat/view/menu/rd1;->m:Landroidx/appcompat/view/menu/md1;

    invoke-virtual {v2}, Landroidx/appcompat/view/menu/md1;->a()I

    move-result v2

    invoke-static {v1, v0, v2}, Landroidx/appcompat/view/menu/ud1;->q(Landroidx/appcompat/view/menu/ud1;Landroidx/appcompat/view/menu/df;I)V

    return-void
.end method
