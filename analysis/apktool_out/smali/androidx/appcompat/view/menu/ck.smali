.class public final synthetic Landroidx/appcompat/view/menu/ck;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/cw0$d;

.field public final synthetic n:Landroidx/appcompat/view/menu/bk$g;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/cw0$d;Landroidx/appcompat/view/menu/bk$g;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ck;->m:Landroidx/appcompat/view/menu/cw0$d;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ck;->n:Landroidx/appcompat/view/menu/bk$g;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ck;->m:Landroidx/appcompat/view/menu/cw0$d;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ck;->n:Landroidx/appcompat/view/menu/bk$g;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/bk$g;->j(Landroidx/appcompat/view/menu/cw0$d;Landroidx/appcompat/view/menu/bk$g;)V

    return-void
.end method
