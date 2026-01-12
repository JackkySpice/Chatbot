.class public final synthetic Landroidx/appcompat/view/menu/ik;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/lang/Runnable;


# instance fields
.field public final synthetic m:Landroidx/appcompat/view/menu/bk$g;

.field public final synthetic n:Landroid/view/ViewGroup;


# direct methods
.method public synthetic constructor <init>(Landroidx/appcompat/view/menu/bk$g;Landroid/view/ViewGroup;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/ik;->m:Landroidx/appcompat/view/menu/bk$g;

    iput-object p2, p0, Landroidx/appcompat/view/menu/ik;->n:Landroid/view/ViewGroup;

    return-void
.end method


# virtual methods
.method public final run()V
    .locals 2

    iget-object v0, p0, Landroidx/appcompat/view/menu/ik;->m:Landroidx/appcompat/view/menu/bk$g;

    iget-object v1, p0, Landroidx/appcompat/view/menu/ik;->n:Landroid/view/ViewGroup;

    invoke-static {v0, v1}, Landroidx/appcompat/view/menu/bk$g$b$a;->a(Landroidx/appcompat/view/menu/bk$g;Landroid/view/ViewGroup;)V

    return-void
.end method
