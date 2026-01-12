.class public final Landroidx/appcompat/view/menu/e52;
.super Landroidx/appcompat/view/menu/xg1;
.source "SourceFile"


# instance fields
.field public final synthetic e:Landroidx/appcompat/view/menu/d42;


# direct methods
.method public constructor <init>(Landroidx/appcompat/view/menu/d42;Landroidx/appcompat/view/menu/ez1;)V
    .locals 0

    iput-object p1, p0, Landroidx/appcompat/view/menu/e52;->e:Landroidx/appcompat/view/menu/d42;

    invoke-direct {p0, p2}, Landroidx/appcompat/view/menu/xg1;-><init>(Landroidx/appcompat/view/menu/ez1;)V

    return-void
.end method


# virtual methods
.method public final d()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/e52;->e:Landroidx/appcompat/view/menu/d42;

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/bz1;->l()Landroidx/appcompat/view/menu/lt1;

    move-result-object v0

    invoke-virtual {v0}, Landroidx/appcompat/view/menu/lt1;->L()Landroidx/appcompat/view/menu/ot1;

    move-result-object v0

    const-string v1, "Tasks have been queued for a long time"

    invoke-virtual {v0, v1}, Landroidx/appcompat/view/menu/ot1;->a(Ljava/lang/String;)V

    return-void
.end method
