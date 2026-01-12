.class public final synthetic Landroidx/appcompat/view/menu/pq;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Landroid/view/View$OnClickListener;


# instance fields
.field public final synthetic a:Landroid/webkit/WebView;


# direct methods
.method public synthetic constructor <init>(Landroid/webkit/WebView;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Landroidx/appcompat/view/menu/pq;->a:Landroid/webkit/WebView;

    return-void
.end method


# virtual methods
.method public final onClick(Landroid/view/View;)V
    .locals 1

    iget-object v0, p0, Landroidx/appcompat/view/menu/pq;->a:Landroid/webkit/WebView;

    invoke-static {v0, p1}, Landroidx/appcompat/view/menu/tq;->b(Landroid/webkit/WebView;Landroid/view/View;)V

    return-void
.end method
