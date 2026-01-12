.class public final Landroidx/appcompat/view/menu/y82;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroidx/appcompat/view/menu/x92;


# instance fields
.field public final synthetic a:Landroidx/appcompat/view/menu/k82;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/k82;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/y82;->a:Landroidx/appcompat/view/menu/k82;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final l(Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V
    .locals 2

    invoke-static {p1}, Landroid/text/TextUtils;->isEmpty(Ljava/lang/CharSequence;)Z

    move-result v0

    if-eqz v0, :cond_0

    iget-object p1, p0, Landroidx/appcompat/view/menu/y82;->a:Landroidx/appcompat/view/menu/k82;

    invoke-static {p1}, Landroidx/appcompat/view/menu/k82;->i(Landroidx/appcompat/view/menu/k82;)Landroidx/appcompat/view/menu/yw1;

    move-result-object p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Landroidx/appcompat/view/menu/y82;->a:Landroidx/appcompat/view/menu/k82;

    invoke-static {p1}, Landroidx/appcompat/view/menu/k82;->i(Landroidx/appcompat/view/menu/k82;)Landroidx/appcompat/view/menu/yw1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/yw1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object p1

    invoke-virtual {p1}, Landroidx/appcompat/view/menu/lt1;->G()Landroidx/appcompat/view/menu/ot1;

    move-result-object p1

    const-string p3, "AppId not known when logging event"

    invoke-virtual {p1, p3, p2}, Landroidx/appcompat/view/menu/ot1;->b(Ljava/lang/String;Ljava/lang/Object;)V

    return-void

    :cond_0
    iget-object v0, p0, Landroidx/appcompat/view/menu/y82;->a:Landroidx/appcompat/view/menu/k82;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/k82;->h()Landroidx/appcompat/view/menu/fw1;

    move-result-object v0

    new-instance v1, Landroidx/appcompat/view/menu/w82;

    invoke-direct {v1, p0, p1, p2, p3}, Landroidx/appcompat/view/menu/w82;-><init>(Landroidx/appcompat/view/menu/y82;Ljava/lang/String;Ljava/lang/String;Landroid/os/Bundle;)V

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/fw1;->D(Ljava/lang/Runnable;)V

    :cond_1
    return-void
.end method
